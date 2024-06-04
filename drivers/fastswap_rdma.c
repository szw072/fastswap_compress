#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include "fastswap_rdma.h"
#include <linux/slab.h>
#include <linux/cpumask.h>
#include <linux/crc16.h>

#include <linux/rbtree.h>
#include <linux/lzo.h>

static struct sswap_rdma_ctrl *gctrl;
static int serverport;
static int numqueues;
static int numcpus;
static char serverip[INET_ADDRSTRLEN];
static char clientip[INET_ADDRSTRLEN];
static struct kmem_cache *req_cache;
module_param_named(sport, serverport, int, 0644);

// modified by ysjing
// module_param_named(nq, numqueues, int, 0644);
module_param_named(nc, numcpus, int, 0644);//numqueues = numcpus * 3 = 60;

module_param_string(sip, serverip, INET_ADDRSTRLEN, 0644);
module_param_string(cip, clientip, INET_ADDRSTRLEN, 0644);

// TODO: destroy ctrl

#define CONNECTION_TIMEOUT_MS 60000
// #define QP_QUEUE_DEPTH 256
#define QP_QUEUE_DEPTH 15000
// #define QP_QUEUE_DEPTH 40000
/* we don't really use recv wrs, so any small number should do */
#define QP_MAX_RECV_WR 4
/* we mainly do send wrs */
#define QP_MAX_SEND_WR	(4096)
#define CQ_NUM_CQES	(QP_MAX_SEND_WR)
#define POLL_BATCH_HIGH (QP_MAX_SEND_WR / 4)

struct zswap_entry {
	struct rb_node rbnode;
	pgoff_t offset;
	int refcount;//用concurrent load时,保护entry不被过早释放
	size_t length;//+++
  u16 crc_uncompress, crc_compress;//++++
};
struct zswap_tree {//包含rb树root
	struct rb_root rbroot;
	spinlock_t lock;
};
static struct zswap_tree *zswap_trees;//rb tree数组,只一个swap area,申请一个


// static atomic_t local_stored_pages = ATOMIC_INIT(0);//未压缩成功存到本地dram数量
static atomic_t zswap_stored_pages = ATOMIC_INIT(0);//存到页面数量

/*********************************
* lzo decompress functions
**********************************/

static void decompress_buf_read_lzo(struct rdma_req *req){
  u16 crc_r, crc_r_decompress;
  void *dst;
  int ret;
  size_t page_len = PAGE_SIZE;

  dst = kmap_atomic(req->page);
  crc_r = crc16(0x0000 ,req->src, req->len);

  // pr_info("--> jump tp decompress_buf_read_alloc_free()");

  if(req->len == 4096){
    if(req->crc_uncompress != crc_r){
      pr_err("[!!!] uncompress crc wrong!!! cpuid: %d offset: %llx crc write: %hx read: %hx",smp_processor_id(), req->roffset, req->crc_uncompress, crc_r);
      goto out;
    }
    memcpy(dst, req->src, req->len);
    // pr_info("[done] uncompress cpuid: %d offset: %llx crc: %hx",smp_processor_id(), req->roffset, crc_r);
  }
  else{
    if(req->crc_compress != crc_r){
      pr_err("[!!!] compress crc wrong!!! cpuid: %d offset: %llx crc write: %hx read: %hx",smp_processor_id(), req->roffset, req->crc_compress, crc_r);
      goto out;
    }
      
    // decompress_ret = crypto_comp_decompress(tfm, req->src, req->len, dst, &slen);
    
    ret = lzo1x_decompress_safe(req->src, req->len, dst, &page_len); 


    if(ret != 0){
      pr_err("[done back] decompress wrong!!! ret: %d", ret);
      goto out;
    }
    crc_r_decompress = crc16(0x0000, dst, page_len);
    // pr_info("[*read done] decompress cpuid: %d offset: %llx len: %zu --> %zu ret: %d", smp_processor_id(), req->roffset, req->len, page_len, ret);
    // pr_info("[----------] crc: %hx --> %hx | %hx --> %hx", req->crc_uncompress, req->crc_compress, crc_r, crc_r_decompress);
  }
out:
  kunmap_atomic(dst);
  // kfree(req->src);//先不释放
  // pr_info("<-- jump back");
}


/*********************************
* rb tree functions 
**********************************/
static void zswap_rb_erase(struct rb_root *root, struct zswap_entry *entry)
{
	if (!RB_EMPTY_NODE(&entry->rbnode)) {
		rb_erase(&entry->rbnode, root);
		RB_CLEAR_NODE(&entry->rbnode);
	}
}

static int zswap_rb_insert(struct rb_root *root, struct zswap_entry *entry,//如果rb树上发现重复的entry,dupenry指向重复的entry
			struct zswap_entry **dupentry)
{//zswap_entry
	struct rb_node **link = &root->rb_node, *parent = NULL;
	struct zswap_entry *myentry;

	while (*link) {
		parent = *link;//entry是带插入rb tree的entry, link是指向rb tree的节点的指针
		myentry = rb_entry(parent, struct zswap_entry, rbnode);//#define rb_entry(ptr, type, member) container_of(ptr, type, member)
		if (myentry->offset > entry->offset)//如果新节点的offset小于父亲节点的offset
			link = &(*link)->rb_left;
		else if (myentry->offset < entry->offset)//如果新节点的offset大于父亲节点的offset
			link = &(*link)->rb_right;
		else {//如果新节点的offset等于父亲节点的offset
			*dupentry = myentry;
			return -EEXIST;
		}
	}
	rb_link_node(&entry->rbnode, parent, link);//插入 把新节点指向其父亲节点
	rb_insert_color(&entry->rbnode, root);//rb树颜色的调整
	return 0;
}

static struct zswap_entry *zswap_rb_search(struct rb_root *root, pgoff_t offset)
{
	struct rb_node *node = root->rb_node;
	struct zswap_entry *entry;

	while (node) {
		entry = rb_entry(node, struct zswap_entry, rbnode);
		if (entry->offset > offset)
			node = node->rb_left;
		else if (entry->offset < offset)
			node = node->rb_right;
		else
			return entry;
	}
	return NULL;
}

/* caller must hold the tree lock */
static struct zswap_entry *zswap_entry_find_get(struct rb_root *root,
				pgoff_t offset)//根据offset查entry
{
	struct zswap_entry *entry;

	entry = zswap_rb_search(root, offset);
	// if (entry) 
		// entry->refcount++;//用于设置refcount++

	return entry;
}

/* caller must hold the tree lock
* remove from the tree and free it, if nobody reference the entry
*/
//TODO 使用了refcount 最后也没有使用
// static void zswap_entry_put(struct zswap_tree *tree, 
// 			struct zswap_entry *entry)
// {
// 	// int refcount = --entry->refcount;
// 	// BUG_ON(refcount < 0);
// 	// if (refcount == 0) {
// 	// 	zswap_rb_erase(&tree->rbroot, entry);
// 	// 	zswap_free_entry(entry);
// 	// }
//   zswap_rb_erase(&tree->rbroot, entry);
//   kfree(entry);
// }
//

static void zswap_frontswap_invalidate_area(void)
{
	struct zswap_tree *tree = zswap_trees;
	struct zswap_entry *entry, *n;

	if (!tree)
		return;

	/* walk the tree and free everything */
	spin_lock(&tree->lock);
	rbtree_postorder_for_each_entry_safe(entry, n, &tree->rbroot, rbnode){//先序遍历
    kfree(entry);
    atomic_dec(&zswap_stored_pages);
  }
	tree->rbroot = RB_ROOT;
	spin_unlock(&tree->lock);
	kfree(tree);
	zswap_trees = NULL;
}


void init_rbtree(void){
  struct zswap_tree *tree;//
  // int i;

  tree = kzalloc(sizeof(struct zswap_tree), GFP_KERNEL);//为swap(rb) tree分配空间,包含一个rbroot和lock

  if (!tree) {
    pr_err("alloc failed, zswap disabled for swap type \n");
    BUG();
    return;
  }

  tree->rbroot = RB_ROOT;//为NULL #define RB_ROOT	(struct rb_root) { NULL, }
  spin_lock_init(&tree->lock);
  zswap_trees = tree;
}

static void sswap_rdma_addone(struct ib_device *dev)
{
  pr_info("sswap_rdma_addone() = %s\n", dev->name);
}

static void sswap_rdma_removeone(struct ib_device *ib_device, void *client_data)
{
  pr_info("sswap_rdma_removeone()\n");
}

static struct ib_client sswap_rdma_ib_client = {
  .name   = "sswap_rdma",
  .add    = sswap_rdma_addone,
  .remove = sswap_rdma_removeone
};

static struct sswap_rdma_dev *sswap_rdma_get_device(struct rdma_queue *q)
{
  struct sswap_rdma_dev *rdev = NULL;

  if (!q->ctrl->rdev) {
    rdev = kzalloc(sizeof(*rdev), GFP_KERNEL);
    if (!rdev) {
      pr_err("no memory\n");
      goto out_err;
    }

    rdev->dev = q->cm_id->device;

    pr_info("selecting device %s\n", rdev->dev->name);

    rdev->pd = ib_alloc_pd(rdev->dev, 0);
    if (IS_ERR(rdev->pd)) {
      pr_err("ib_alloc_pd\n");
      goto out_free_dev;
    }

    if (!(rdev->dev->attrs.device_cap_flags &
          IB_DEVICE_MEM_MGT_EXTENSIONS)) {
      pr_err("memory registrations not supported\n");
      goto out_free_pd;
    }

    q->ctrl->rdev = rdev;
  }

  return q->ctrl->rdev;

out_free_pd:
  ib_dealloc_pd(rdev->pd);
out_free_dev:
  kfree(rdev);
out_err:
  return NULL;
}

static void sswap_rdma_qp_event(struct ib_event *e, void *c)
{
  pr_info("sswap_rdma_qp_event\n");
}

static int sswap_rdma_create_qp(struct rdma_queue *queue)
{
  struct sswap_rdma_dev *rdev = queue->ctrl->rdev;
  struct ib_qp_init_attr init_attr;
  int ret;

  pr_info("start: %s\n", __FUNCTION__);

  memset(&init_attr, 0, sizeof(init_attr));
  init_attr.event_handler = sswap_rdma_qp_event;
  init_attr.cap.max_send_wr = QP_MAX_SEND_WR;
  init_attr.cap.max_recv_wr = QP_MAX_RECV_WR;
  init_attr.cap.max_recv_sge = 1;
  init_attr.cap.max_send_sge = 1;
  init_attr.sq_sig_type = IB_SIGNAL_REQ_WR;
  init_attr.qp_type = IB_QPT_RC;
  init_attr.send_cq = queue->cq;
  init_attr.recv_cq = queue->cq;
  /* just to check if we are compiling against the right headers */
  init_attr.create_flags = IB_QP_EXP_CREATE_ATOMIC_BE_REPLY & 0;

  ret = rdma_create_qp(queue->cm_id, rdev->pd, &init_attr);
  if (ret) {
    pr_err("rdma_create_qp failed: %d\n", ret);
    return ret;
  }

  queue->qp = queue->cm_id->qp;
  return ret;
}

static void sswap_rdma_destroy_queue_ib(struct rdma_queue *q)
{
  struct sswap_rdma_dev *rdev;
  struct ib_device *ibdev;

  pr_info("start: %s\n", __FUNCTION__);

  rdev = q->ctrl->rdev;
  ibdev = rdev->dev;
  //rdma_destroy_qp(q->ctrl->cm_id);
  ib_free_cq(q->cq);
}

static int sswap_rdma_create_queue_ib(struct rdma_queue *q)
{
  struct ib_device *ibdev = q->ctrl->rdev->dev;
  int ret;
  int comp_vector = 0;

  pr_info("start: %s\n", __FUNCTION__);

  if (q->qp_type == QP_READ_ASYNC)
    q->cq = ib_alloc_cq(ibdev, q, CQ_NUM_CQES,
      comp_vector, IB_POLL_SOFTIRQ);
  else
    q->cq = ib_alloc_cq(ibdev, q, CQ_NUM_CQES,
      comp_vector, IB_POLL_DIRECT);

  if (IS_ERR(q->cq)) {
    ret = PTR_ERR(q->cq);
    goto out_err;
  }

  ret = sswap_rdma_create_qp(q);
  if (ret)
    goto out_destroy_ib_cq;

  return 0;

out_destroy_ib_cq:
  ib_free_cq(q->cq);
out_err:
  return ret;
}

static int sswap_rdma_addr_resolved(struct rdma_queue *q)
{
  struct sswap_rdma_dev *rdev = NULL;
  int ret;

  pr_info("start: %s\n", __FUNCTION__);

  rdev = sswap_rdma_get_device(q);
  if (!rdev) {
    pr_err("no device found\n");
    return -ENODEV;
  }

  ret = sswap_rdma_create_queue_ib(q);
  if (ret) {
    return ret;
  }

  ret = rdma_resolve_route(q->cm_id, CONNECTION_TIMEOUT_MS);
  if (ret) {
    pr_err("rdma_resolve_route failed\n");
    sswap_rdma_destroy_queue_ib(q);
  }

  return 0;
}

static int sswap_rdma_route_resolved(struct rdma_queue *q,
    struct rdma_conn_param *conn_params)
{
  struct rdma_conn_param param = {};
  int ret;

  param.qp_num = q->qp->qp_num;
  param.flow_control = 1;
  param.responder_resources = 16;
  param.initiator_depth = 16;
  param.retry_count = 7;
  param.rnr_retry_count = 7;
  param.private_data = NULL;
  param.private_data_len = 0;

  pr_info("max_qp_rd_atom=%d max_qp_init_rd_atom=%d\n",
      q->ctrl->rdev->dev->attrs.max_qp_rd_atom,
      q->ctrl->rdev->dev->attrs.max_qp_init_rd_atom);

  ret = rdma_connect(q->cm_id, &param);
  if (ret) {
    pr_err("rdma_connect failed (%d)\n", ret);
    sswap_rdma_destroy_queue_ib(q);
  }

  return 0;
}

static int sswap_rdma_conn_established(struct rdma_queue *q)
{
  pr_info("connection established\n");
  return 0;
}

static int sswap_rdma_cm_handler(struct rdma_cm_id *cm_id,
    struct rdma_cm_event *ev)
{
  struct rdma_queue *queue = cm_id->context;
  int cm_error = 0;

  pr_info("cm_handler msg: %s (%d) status %d id %p\n", rdma_event_msg(ev->event),
    ev->event, ev->status, cm_id);

  switch (ev->event) {
  case RDMA_CM_EVENT_ADDR_RESOLVED:
    cm_error = sswap_rdma_addr_resolved(queue);
    break;
  case RDMA_CM_EVENT_ROUTE_RESOLVED:
    cm_error = sswap_rdma_route_resolved(queue, &ev->param.conn);
    break;
  case RDMA_CM_EVENT_ESTABLISHED:
    queue->cm_error = sswap_rdma_conn_established(queue);
    /* complete cm_done regardless of success/failure */
    complete(&queue->cm_done);
    return 0;
  case RDMA_CM_EVENT_REJECTED:
    pr_err("connection rejected\n");
    break;
  case RDMA_CM_EVENT_ADDR_ERROR:
  case RDMA_CM_EVENT_ROUTE_ERROR:
  case RDMA_CM_EVENT_CONNECT_ERROR:
  case RDMA_CM_EVENT_UNREACHABLE:
    pr_err("CM error event %d\n", ev->event);
    cm_error = -ECONNRESET;
    break;
  case RDMA_CM_EVENT_DISCONNECTED:
  case RDMA_CM_EVENT_ADDR_CHANGE:
  case RDMA_CM_EVENT_TIMEWAIT_EXIT:
    pr_err("CM connection closed %d\n", ev->event);
    break;
  case RDMA_CM_EVENT_DEVICE_REMOVAL:
    /* device removal is handled via the ib_client API */
    break;
  default:
    pr_err("CM unexpected event: %d\n", ev->event);
    break;
  }

  if (cm_error) {
    queue->cm_error = cm_error;
    complete(&queue->cm_done);
  }

  return 0;
}

inline static int sswap_rdma_wait_for_cm(struct rdma_queue *queue)
{
  wait_for_completion_interruptible_timeout(&queue->cm_done,
    msecs_to_jiffies(CONNECTION_TIMEOUT_MS) + 1);
  return queue->cm_error;
}

static int sswap_rdma_init_queue(struct sswap_rdma_ctrl *ctrl,
    int idx)
{
  struct rdma_queue *queue;
  int ret;

  pr_info("start: %s\n", __FUNCTION__);

  queue = &ctrl->queues[idx];
  queue->ctrl = ctrl;
  init_completion(&queue->cm_done);
  atomic_set(&queue->pending, 0);
  spin_lock_init(&queue->cq_lock);
  queue->qp_type = get_queue_type(idx);

  queue->cm_id = rdma_create_id(&init_net, sswap_rdma_cm_handler, queue,
      RDMA_PS_TCP, IB_QPT_RC);
  if (IS_ERR(queue->cm_id)) {
    pr_err("failed to create cm id: %ld\n", PTR_ERR(queue->cm_id));
    return -ENODEV;
  }

  queue->cm_error = -ETIMEDOUT;

  ret = rdma_resolve_addr(queue->cm_id, &ctrl->srcaddr, &ctrl->addr,
      CONNECTION_TIMEOUT_MS);
  if (ret) {
    pr_err("rdma_resolve_addr failed: %d\n", ret);
    goto out_destroy_cm_id;
  }

  ret = sswap_rdma_wait_for_cm(queue);
  if (ret) {
    pr_err("sswap_rdma_wait_for_cm failed\n");
    goto out_destroy_cm_id;
  }

  return 0;

out_destroy_cm_id:
  rdma_destroy_id(queue->cm_id);
  return ret;
}

static void sswap_rdma_stop_queue(struct rdma_queue *q)
{
  rdma_disconnect(q->cm_id);
}

static void sswap_rdma_free_queue(struct rdma_queue *q)
{
  rdma_destroy_qp(q->cm_id);
  ib_free_cq(q->cq);
  rdma_destroy_id(q->cm_id);
}

static int sswap_rdma_init_queues(struct sswap_rdma_ctrl *ctrl)
{
  int ret, i;
  for (i = 0; i < numqueues; ++i) {
    ret = sswap_rdma_init_queue(ctrl, i);
    if (ret) {
      pr_err("failed to initialized queue: %d\n", i);
      goto out_free_queues;
    }
  }

  return 0;

out_free_queues:
  for (i--; i >= 0; i--) {
    sswap_rdma_stop_queue(&ctrl->queues[i]);
    sswap_rdma_free_queue(&ctrl->queues[i]);
  }

  return ret;
}

static void sswap_rdma_stopandfree_queues(struct sswap_rdma_ctrl *ctrl)
{
  int i;
  for (i = 0; i < numqueues; ++i) {
    sswap_rdma_stop_queue(&ctrl->queues[i]);
    sswap_rdma_free_queue(&ctrl->queues[i]);
  }
}

static int sswap_rdma_parse_ipaddr(struct sockaddr_in *saddr, char *ip)
{
  u8 *addr = (u8 *)&saddr->sin_addr.s_addr;
  size_t buflen = strlen(ip);

  pr_info("start: %s\n", __FUNCTION__);

  if (buflen > INET_ADDRSTRLEN)
    return -EINVAL;
  if (in4_pton(ip, buflen, addr, '\0', NULL) == 0)
    return -EINVAL;
  saddr->sin_family = AF_INET;
  return 0;
}

static int sswap_rdma_create_ctrl(struct sswap_rdma_ctrl **c)
{
  int ret;
  struct sswap_rdma_ctrl *ctrl;
  pr_info("will try to connect to %s:%d\n", serverip, serverport);

  *c = kzalloc(sizeof(struct sswap_rdma_ctrl), GFP_KERNEL);
  if (!*c) {
    pr_err("no mem for ctrl\n");
    return -ENOMEM;
  }
  ctrl = *c;

  ctrl->queues = kzalloc(sizeof(struct rdma_queue) * numqueues, GFP_KERNEL);
  ret = sswap_rdma_parse_ipaddr(&(ctrl->addr_in), serverip);
  if (ret) {
    pr_err("sswap_rdma_parse_ipaddr failed: %d\n", ret);
    return -EINVAL;
  }
  ctrl->addr_in.sin_port = cpu_to_be16(serverport);

  ret = sswap_rdma_parse_ipaddr(&(ctrl->srcaddr_in), clientip);
  if (ret) {
    pr_err("sswap_rdma_parse_ipaddr failed: %d\n", ret);
    return -EINVAL;
  }
  /* no need to set the port on the srcaddr */

  return sswap_rdma_init_queues(ctrl);
}

static void __exit sswap_rdma_cleanup_module(void)
{
  sswap_rdma_stopandfree_queues(gctrl);
  ib_unregister_client(&sswap_rdma_ib_client);
  kfree(gctrl);
  gctrl = NULL;
  if (req_cache) {
    kmem_cache_destroy(req_cache);
  }
  zswap_frontswap_invalidate_area();
}

static void sswap_rdma_write_done(struct ib_cq *cq, struct ib_wc *wc)
{
  struct rdma_req *req =
    container_of(wc->wr_cqe, struct rdma_req, cqe);
  struct rdma_queue *q = cq->cq_context;
  struct ib_device *ibdev = q->ctrl->rdev->dev;
  size_t page_len = PAGE_SIZE;

  if (unlikely(wc->status != IB_WC_SUCCESS)) {
    pr_err("sswap_rdma_write_done status is not success, it is=%d\n", wc->status);
    //q->write_error = wc->status;
  }
  // ib_dma_unmap_page(ibdev, req->dma, PAGE_SIZE, DMA_TO_DEVICE);// 修改接口后这里 req->dma 是page kmap到的内核虚拟地址 
  ib_dma_unmap_single(ibdev, req->dma, req->len, DMA_TO_DEVICE);

  // pr_info("[write done] cpuid: %d offset: %llx len: %zu --> %zu crc: %hx --> %hx", smp_processor_id(), req->roffset, page_len, req->len, req->crc_uncompress, req->crc_compress);

  complete(&req->done);//添加写同步


  atomic_dec(&q->pending);
  kfree(req->src);//释放write buf
  kmem_cache_free(req_cache, req);
}

static void sswap_rdma_read_done(struct ib_cq *cq, struct ib_wc *wc)
{
  struct rdma_req *req =
    container_of(wc->wr_cqe, struct rdma_req, cqe);
  struct rdma_queue *q = cq->cq_context;
  struct ib_device *ibdev = q->ctrl->rdev->dev;



  if (unlikely(wc->status != IB_WC_SUCCESS))
    pr_err("sswap_rdma_read_done status is not success, it is=%d\n", wc->status);

  ib_dma_unmap_single(ibdev, req->dma, req->len, DMA_FROM_DEVICE);
  decompress_buf_read_lzo(req);


  complete(&req->done);
  atomic_dec(&q->pending);
  
  SetPageUptodate(req->page);//
  unlock_page(req->page);//
  kfree(req->src);//
  kmem_cache_free(req_cache, req);//
}

inline static int sswap_rdma_post_rdma(struct rdma_queue *q, struct rdma_req *qe,
  struct ib_sge *sge, u64 roffset, enum ib_wr_opcode op)
{
  const struct ib_send_wr *bad_wr;
  struct ib_rdma_wr rdma_wr = {};
  int ret;

  BUG_ON(qe->dma == 0);

  sge->addr = qe->dma;
  // sge->length = PAGE_SIZE;
  sge->length = qe->len;//按照rdma_req设置长度
  sge->lkey = q->ctrl->rdev->pd->local_dma_lkey;

  /* TODO: add a chain of WR, we already have a list so should be easy
   * to just post requests in batches */
  rdma_wr.wr.next    = NULL;
  rdma_wr.wr.wr_cqe  = &qe->cqe;
  rdma_wr.wr.sg_list = sge;
  rdma_wr.wr.num_sge = 1;
  rdma_wr.wr.opcode  = op;
  rdma_wr.wr.send_flags = IB_SEND_SIGNALED;
  rdma_wr.remote_addr = q->ctrl->servermr.baseaddr + roffset;
  rdma_wr.rkey = q->ctrl->servermr.key;

  atomic_inc(&q->pending);
  ret = ib_post_send(q->qp, &rdma_wr.wr, &bad_wr);
  if (unlikely(ret)) {
    pr_err("ib_post_send failed: %d\n", ret);
  }

  return ret;
}

static void sswap_rdma_recv_remotemr_done(struct ib_cq *cq, struct ib_wc *wc)
{
  struct rdma_req *qe =
    container_of(wc->wr_cqe, struct rdma_req, cqe);
  struct rdma_queue *q = cq->cq_context;
  struct sswap_rdma_ctrl *ctrl = q->ctrl;
  struct ib_device *ibdev = q->ctrl->rdev->dev;

  if (unlikely(wc->status != IB_WC_SUCCESS)) {
    pr_err("sswap_rdma_recv_done status is not success\n");
    return;
  }
  ib_dma_unmap_single(ibdev, qe->dma, sizeof(struct sswap_rdma_memregion),
		      DMA_FROM_DEVICE);
  pr_info("servermr baseaddr=%llx, key=%u\n", ctrl->servermr.baseaddr,
	  ctrl->servermr.key);
  complete_all(&qe->done);
}

static int sswap_rdma_post_recv(struct rdma_queue *q, struct rdma_req *qe,
  size_t bufsize)
{
  const struct ib_recv_wr *bad_wr;
  struct ib_recv_wr wr = {};
  struct ib_sge sge;
  int ret;

  sge.addr = qe->dma;
  sge.length = bufsize;
  sge.lkey = q->ctrl->rdev->pd->local_dma_lkey;

  wr.next    = NULL;
  wr.wr_cqe  = &qe->cqe;
  wr.sg_list = &sge;
  wr.num_sge = 1;

  ret = ib_post_recv(q->qp, &wr, &bad_wr);
  if (ret) {
    pr_err("ib_post_recv failed: %d\n", ret);
  }
  return ret;
}

/* allocates a sswap rdma request, creates a dma mapping for it in
 * req->dma, and synchronizes the dma mapping in the direction of
 * the dma map.
 * Don't touch the page with cpu after creating the request for it!
 * Deallocates the request if there was an error */
inline static int get_req_for_page(struct rdma_req **req, struct ib_device *dev,
				struct page *page, enum dma_data_direction dir)
{
  int ret;

  ret = 0;
  *req = kmem_cache_alloc(req_cache, GFP_ATOMIC);
  if (unlikely(!req)) {
    pr_err("no memory for req\n");
    ret = -ENOMEM;
    goto out;
  }

  (*req)->page = page;
  init_completion(&(*req)->done);

  (*req)->dma = ib_dma_map_page(dev, page, 0, PAGE_SIZE, dir);//这里page是high memory需要使用
  if (unlikely(ib_dma_mapping_error(dev, (*req)->dma))) {
    pr_err("ib_dma_mapping_error\n");
    ret = -ENOMEM;
    kmem_cache_free(req_cache, req);
    goto out;
  }

  ib_dma_sync_single_for_device(dev, (*req)->dma, PAGE_SIZE, dir);
out:
  return ret;
}

/* the buffer needs to come from kernel (not high memory) */
inline static int get_req_for_buf(struct rdma_req **req, struct ib_device *dev,
				void *buf, size_t size,
				enum dma_data_direction dir)
{
  int ret;

  ret = 0;
  *req = kmem_cache_alloc(req_cache, GFP_ATOMIC);
  if (unlikely(!req)) {
    pr_err("no memory for req\n");
    ret = -ENOMEM;
    goto out;
  }

  init_completion(&(*req)->done);//+++++

  (*req)->dma = ib_dma_map_single(dev, buf, size, dir);
  if (unlikely(ib_dma_mapping_error(dev, (*req)->dma))) {
    pr_err("ib_dma_mapping_error\n");
    ret = -ENOMEM;
    kmem_cache_free(req_cache, req);
    goto out;
  }

  ib_dma_sync_single_for_device(dev, (*req)->dma, size, dir);
out:
  return ret;
}

inline static void sswap_rdma_wait_completion(struct ib_cq *cq,
					      struct rdma_req *qe)
{
  ndelay(1000);
  while (!completion_done(&qe->done)) {
    ndelay(250);
    ib_process_cq_direct(cq, 1);
  }
}

/* polls queue until we reach target completed wrs or qp is empty */
static inline int poll_target(struct rdma_queue *q, int target)
{
  unsigned long flags;
  int completed = 0;

  while (completed < target && atomic_read(&q->pending) > 0) {
    spin_lock_irqsave(&q->cq_lock, flags);
    completed += ib_process_cq_direct(q->cq, target - completed);
    spin_unlock_irqrestore(&q->cq_lock, flags);
    cpu_relax();
  }

  return completed;
}

static inline int drain_queue(struct rdma_queue *q)
{
  unsigned long flags;

  while (atomic_read(&q->pending) > 0) {
    spin_lock_irqsave(&q->cq_lock, flags);
    ib_process_cq_direct(q->cq, 16);
    spin_unlock_irqrestore(&q->cq_lock, flags);
    cpu_relax();
  }

  return 1;
}

static inline int write_queue_add(struct rdma_queue *q, struct page *page,
				  u64 roffset)
{
  struct rdma_req *req;
  struct ib_device *dev = q->ctrl->rdev->dev;
  struct ib_sge sge = {};
  int ret, inflight;
  void *src;
  size_t page_len = PAGE_SIZE, wlen;
  void *buf_write, *compress_buf = NULL, *uncompress_buf = NULL;
  u16 crc_uncompress, crc_compress;

  struct zswap_tree *tree = zswap_trees;//每个swap area对应一个rb树 这里只使用一个
  struct zswap_entry *entry = NULL, *dupentry;

  void *wrkmem;

  wrkmem = kmalloc(LZO1X_1_MEM_COMPRESS, GFP_KERNEL);


  while ((inflight = atomic_read(&q->pending)) >= QP_MAX_SEND_WR - 8) {
    BUG_ON(inflight > QP_MAX_SEND_WR);
    poll_target(q, 2048);
    pr_info_ratelimited("back pressure writes");
  }

  src = kmap_atomic(page);
  uncompress_buf = kmalloc(page_len, GFP_KERNEL);//作未压缩page内容的rdma写buf
  if(uncompress_buf == NULL){
    pr_err("kmalloc wrong!!!");
    BUG();
  }
  compress_buf = kmalloc(2 *  page_len, GFP_KERNEL);//压缩目的地址
  if(compress_buf == NULL){
    pr_err("kmalloc wrong!!!");
    BUG();
  }
  crc_uncompress = crc16(0x0000, src, page_len);

  //******** 压缩 **************
  ret = lzo1x_1_compress(src, page_len, compress_buf, &wlen, wrkmem);

  if(wlen >= 4096){//不能压缩 使用原page
    crc_compress = crc_uncompress;//不能压缩crc_compress使用crc_uncompress
    kfree(compress_buf);
    memcpy(uncompress_buf, src, PAGE_SIZE);
    buf_write = uncompress_buf;
    wlen = page_len;
  }
  else{//能压缩 使用压缩后数据
    crc_compress = crc16(0x0000, compress_buf, wlen);
    kfree(uncompress_buf);
    buf_write = compress_buf;
  }
  kunmap_atomic(src);

//   pr_info("[write] cpuid: %d offset: %llx len: %zu --> %zu crc: %hx --> %hx ret: %d", smp_processor_id(), roffset, page_len, wlen, crc_uncompress, crc_compress, ret);

  ret = get_req_for_buf(&req, dev, buf_write, wlen, DMA_TO_DEVICE);//设置req中地址dma 长度len

  if (unlikely(ret))
    return ret;
  req->len = wlen;//+++ 用于post请求设置sge
  req->src = buf_write;
  req->crc_compress = crc_compress;
  req->crc_uncompress = crc_uncompress;
  req->roffset = roffset;
  req->cqe.done = sswap_rdma_write_done;//添加同步操作
  ret = sswap_rdma_post_rdma(q, req, &sge, roffset, IB_WR_RDMA_WRITE);

  // sswap_rdma_wait_completion(q->cq, req);//+++++++同步 等待写完成

  //TODO 这里可能有问题 rb tree插入在post请求之后执行 可能存在写未完成 rb tree已经插入 导致读的时候rb tree可以找到entry 但是write还处于inflight状态
  //  但是应该问题不大 因为不在done中unlock page应该不会发起读请求
  //******** 插入rb tree **************
  entry = kmalloc(sizeof(struct zswap_entry), GFP_KERNEL); //申请插入rbtree 的swap entry
  if(entry == NULL){
    pr_err("kmalloc wrong!!!");
    BUG();
  }
  RB_CLEAR_NODE(&entry->rbnode);
  entry->offset = req->roffset;
  entry->length = req->len;
  entry->crc_compress = req->crc_compress;//+++ 用于读校验
  entry->crc_uncompress = req->crc_uncompress;//+++ 用于读校验

  spin_lock(&tree->lock);
	do {
		ret = zswap_rb_insert(&tree->rbroot, entry, &dupentry);
		if (ret == -EEXIST) {//重复的entry 应该删除重复的entry(dupentry)
      // pr_info("[write_duplicate] offset: %lx", entry->offset);
			// zswap_duplicate_entry++;
			/* remove from rbtree */
			zswap_rb_erase(&tree->rbroot, dupentry);
      kfree(dupentry);//释放entry
			// zswap_entry_put(tree, dupentry)
		}
	} while (ret == -EEXIST);
  spin_unlock(&tree->lock);

  kfree(wrkmem);
  return ret;
}

static inline int begin_read(struct rdma_queue *q, struct page *page,
			     u64 roffset)
{
  struct rdma_req *req;
  struct ib_device *dev = q->ctrl->rdev->dev;
  struct ib_sge sge = {};
  int ret, inflight;
  void *buf_read;
  // void *dst;
  // int decompress_ret, slen;
  // u16 crc_r, crc_r_decompress;
  // void *decompress_buf;

  struct zswap_tree *tree = zswap_trees;//每个swap area对应一个rb树 这里只使用一个
  struct zswap_entry *entry;



  // pr_info("[begin_read] roffset: %llx", roffset);//读输出roffset
  /* back pressure in-flight reads, can't send more than
   * QP_MAX_SEND_WR at a time */
  while ((inflight = atomic_read(&q->pending)) >= QP_MAX_SEND_WR) {
    BUG_ON(inflight > QP_MAX_SEND_WR); /* only valid case is == */
    poll_target(q, 8);
    pr_info_ratelimited("back pressure happened on reads");
  }

  //******** 查rb tree得dlen **************
	spin_lock(&tree->lock);//lock 防止数据读写冲突
	entry = zswap_entry_find_get(&tree->rbroot, roffset);//1.根据roffset在rb树上查找到entry 包含len 2.refcount++
  if (!entry) {
		/* entry was written back */
		spin_unlock(&tree->lock);
    pr_info("rb treee not found");
    BUG();
		return -1;
	}
	spin_unlock(&tree->lock);//unlock
  // pr_info("found rbtree entry roffest: %lx, length: %d --> %zu crc: %hx --> %hx", entry->offset, 4096, entry->length, entry->crc_uncompress, entry->crc_compress);

  // src = (u8 *)kmap_atomic(page);
  buf_read = kmalloc(PAGE_SIZE, GFP_KERNEL);//作为read buf
  if(buf_read == NULL){
    pr_err("kmalloc wrong!!!");
    BUG();
  }
  ret = get_req_for_buf(&req, dev, buf_read, entry->length, DMA_FROM_DEVICE);

  // ret = get_req_for_page(&req, dev, page, DMA_TO_DEVICE);

  if (unlikely(ret))
    return ret;
  req->len = entry->length;//+++ 用于unmap
  req->roffset = roffset;//+++++
  req->page = page;//+++
  req->src = buf_read;//+++
  req->crc_compress = entry->crc_compress;//+++ 用于解压缩校验
  req->crc_uncompress = entry->crc_uncompress;//+++ 用于解压缩校验
  req->cqe.done = sswap_rdma_read_done;
  ret = sswap_rdma_post_rdma(q, req, &sge, roffset, IB_WR_RDMA_READ);

  // sswap_rdma_wait_completion(q->cq, req);//等待read done完成 这里解压缩移到read_done中 不需要同步

  //******** 解压缩 lzo **************
  // decompress_buf_read_lzo(req);

  // kmem_cache_free(req_cache, req);//不能提前释放
  // kfree(req->src);
  // SetPageUptodate(req->page);
  // unlock_page(req->page);
  return ret;
}

int sswap_rdma_write(struct page *page, u64 roffset)
{
  int ret;
  struct rdma_queue *q;

  VM_BUG_ON_PAGE(!PageSwapCache(page), page);

  q = sswap_rdma_get_queue(smp_processor_id(), QP_WRITE_SYNC);
  ret = write_queue_add(q, page, roffset);
  BUG_ON(ret);
  drain_queue(q);
  return ret;
}
EXPORT_SYMBOL(sswap_rdma_write);

static int sswap_rdma_recv_remotemr(struct sswap_rdma_ctrl *ctrl)
{
  struct rdma_req *qe;
  int ret;
  struct ib_device *dev;

  pr_info("start: %s\n", __FUNCTION__);
  dev = ctrl->rdev->dev;

  ret = get_req_for_buf(&qe, dev, &(ctrl->servermr), sizeof(ctrl->servermr),
			DMA_FROM_DEVICE);
  if (unlikely(ret))
    goto out;

  qe->cqe.done = sswap_rdma_recv_remotemr_done;

  ret = sswap_rdma_post_recv(&(ctrl->queues[0]), qe, sizeof(struct sswap_rdma_memregion));

  if (unlikely(ret))
    goto out_free_qe;

  /* this delay doesn't really matter, only happens once */
  sswap_rdma_wait_completion(ctrl->queues[0].cq, qe);

out_free_qe:
  kmem_cache_free(req_cache, qe);
out:
  return ret;
}

/* page is unlocked when the wr is done.
 * posts an RDMA read on this cpu's qp */
int sswap_rdma_read_async(struct page *page, u64 roffset)
{
  struct rdma_queue *q;
  int ret;

  VM_BUG_ON_PAGE(!PageSwapCache(page), page);
  VM_BUG_ON_PAGE(!PageLocked(page), page);
  VM_BUG_ON_PAGE(PageUptodate(page), page);

  q = sswap_rdma_get_queue(smp_processor_id(), QP_READ_ASYNC);
  ret = begin_read(q, page, roffset);
  return ret;
}
EXPORT_SYMBOL(sswap_rdma_read_async);

int sswap_rdma_read_sync(struct page *page, u64 roffset)
{
  struct rdma_queue *q;
  int ret;

  VM_BUG_ON_PAGE(!PageSwapCache(page), page);
  VM_BUG_ON_PAGE(!PageLocked(page), page);
  VM_BUG_ON_PAGE(PageUptodate(page), page);

  q = sswap_rdma_get_queue(smp_processor_id(), QP_READ_SYNC);
  ret = begin_read(q, page, roffset);
  return ret;
}
EXPORT_SYMBOL(sswap_rdma_read_sync);

int sswap_rdma_poll_load(int cpu)
{
  struct rdma_queue *q = sswap_rdma_get_queue(cpu, QP_READ_SYNC);
  return drain_queue(q);
}
EXPORT_SYMBOL(sswap_rdma_poll_load);

/* idx is absolute id (i.e. > than number of cpus) */
inline enum qp_type get_queue_type(unsigned int idx)
{
  // numcpus = 8
  if (idx < numcpus)
    return QP_READ_SYNC;
  else if (idx < numcpus * 2)
    return QP_READ_ASYNC;
  else if (idx < numcpus * 3)
    return QP_WRITE_SYNC;

  BUG();
  return QP_READ_SYNC;
}

inline struct rdma_queue *sswap_rdma_get_queue(unsigned int cpuid,
					       enum qp_type type)
{
  BUG_ON(gctrl == NULL);

  switch (type) {
    case QP_READ_SYNC:
      return &gctrl->queues[cpuid];
    case QP_READ_ASYNC:
      return &gctrl->queues[cpuid + numcpus];
    case QP_WRITE_SYNC:
      return &gctrl->queues[cpuid + numcpus * 2];
    default:
      BUG();
  };
}

static int __init sswap_rdma_init_module(void)
{
  int ret;

  pr_info("start: %s\n", __FUNCTION__);
  pr_info("* RDMA BACKEND *");

  // modified by ysjing
  // numcpus = num_online_cpus()
  numqueues = numcpus * 3;

  req_cache = kmem_cache_create("sswap_req_cache", sizeof(struct rdma_req), 0,
                      SLAB_TEMPORARY | SLAB_HWCACHE_ALIGN, NULL);

  if (!req_cache) {
    pr_err("no memory for cache allocation\n");
    return -ENOMEM;
  }

  ib_register_client(&sswap_rdma_ib_client);
  ret = sswap_rdma_create_ctrl(&gctrl);
  if (ret) {
    pr_err("could not create ctrl\n");
    ib_unregister_client(&sswap_rdma_ib_client);
    return -ENODEV;
  }

  ret = sswap_rdma_recv_remotemr(gctrl);
  if (ret) {
    pr_err("could not setup remote memory region\n");
    ib_unregister_client(&sswap_rdma_ib_client);
    return -ENODEV;
  }

  init_rbtree();
  pr_info("ctrl is ready for reqs\n");
  return 0;
}

module_init(sswap_rdma_init_module);
module_exit(sswap_rdma_cleanup_module);

MODULE_LICENSE("GPL v2");
MODULE_DESCRIPTION("Experiments");
