/* vm.c: Generic interface for virtual memory objects. */

#include "vm/vm.h"

#include "threads/malloc.h"
#include "threads/mmu.h"
#include "threads/vaddr.h"
#include "vm/inspect.h"

/* project3 */
extern struct lock filesys_lock;

/* Initializes the virtual memory subsystem by invoking each subsystem's
 * intialize codes. */
void vm_init(void)
{
  vm_anon_init();
  vm_file_init();
#ifdef EFILESYS /* For project 4 */
  pagecache_init();
#endif
  register_inspect_intr();
  /* DO NOT MODIFY UPPER LINES. */
  /* TODO: Your code goes here. */
  /* project3 */
  list_init(&lru);
  lock_init(&lru_lock);
  lock_init(&kill_lock);
}

/* Get the type of the page. This function is useful if you want to know the
 * type of the page after it will be initialized.
 * This function is fully implemented now. */
enum vm_type
page_get_type(struct page *page)
{
  int ty = VM_TYPE(page->operations->type);
  switch (ty)
  {
  case VM_UNINIT:
    return VM_TYPE(page->uninit.type);
  default:
    return ty;
  }
}

/* Helpers */
static struct frame *vm_get_victim(void);
static bool vm_do_claim_page(struct page *page);
static struct frame *vm_evict_frame(void);

/* Create the pending page object with initializer. If you want to create a
 * page, do not create it directly and make it through this function or
 * `vm_alloc_page`. */
/*
  그 후에 uninit_new에서 받아온 type으로 이 uninit type이 어떤 type으로 변할지와 같은 정보들을 page 구조체에 채워준다.

  주어진 VM 타입에 따라 적절한 이니셜라이저로 새 가상 메모리 페이지를 할당 및 초기화하고,
  이를 spt에 삽입하는 역할을 한다.
*/
bool vm_alloc_page_with_initializer(enum vm_type type, void *upage, bool writable,
                                    vm_initializer *init, void *aux) // 이것은 vm_alloc_page_with_initializer가 type(가상 메모리 유형을 나타내는 열거형), upage(할당할 페이지의 가상 주소), writable(a 페이지가 쓰기 가능한지 여부를 나타내는 부울 플래그), 'init'(이니셜라이저 함수에 대한 함수 포인터) 및 'aux'(보조 데이터 포인터).
{
  ASSERT(VM_TYPE(type) != VM_UNINIT)

  struct supplemental_page_table *spt = &thread_current()->spt; // struct supplemental_page_table 유형의 spt 포인터를 선언하고 현재 스레드에 대한 추가 페이지 테이블의 주소를 할당합니다. 보충 페이지 테이블(spt)은 가상 페이지와 해당 물리적 ​​프레임 간의 매핑을 추적합니다.

  // upage = upage + 0x8000000000;
  /* Check wheter the upage is already occupied or not. */
  if (spt_find_page(spt, upage) == NULL) // struct supplemental_page_table 유형의 spt 포인터를 선언하고 현재 스레드에 대한 추가 페이지 테이블의 주소를 할당합니다. 보충 페이지 테이블(spt)은 가상 페이지와 해당 물리적 ​​프레임 간의 매핑을 추적합니다.
  {
    /* TODO: Create the page, fetch the initialier according to the VM type,
     * TODO: and then create "uninit" page struct by calling uninit_new. You
     * TODO: should modify the field after calling the uninit_new. */
    /*
      페이지를 생성하고, 인자로 전달한 vm_type에 맞는 적절한 초기화 함수를 가져와야 하고
      이 함수를 인자로 갖는 uninit_new 함수를 호출하고 "uninit"페이지 구조체를 생성한다.
      uninit_new를 호출한 후 필드를 수정해야 한다.
      spt에 페이지를 삽입한다.
    */
    struct page *pg = (struct page *)malloc(sizeof(struct page)); // malloc 함수를 사용하여 새로운 struct page에 대한 메모리를 할당합니다. struct page는 가상 메모리의 단일 페이지를 나타냅니다.
    if (pg == NULL)
      goto err;

    void *va_rounded = pg_round_down(upage); //  pg_round_down 함수를 사용하여 주어진 가상 주소 upage를 가장 가까운 하위 페이지 경계로 내림합니다. 페이지의 시작 주소가 올바르게 정렬되도록 합니다.
    switch (VM_TYPE(type)) // VM_type에 맞게 switch문을 돌려 vm_type에 맞게 선언한 initializer를 anon/file로 바꿔준다.
    {
    case VM_ANON:
      uninit_new(pg, va_rounded, init, type, aux, anon_initializer); // 가상 메모리 유형이 VM_ANON인 경우 pg(새로 할당된 페이지), va_rounded(내림된 가상 주소), init(이니셜라이저 함수 포인터)로 uninit_new 함수를 호출합니다. type(가상 메모리 유형), aux(보조 데이터) 및 anon_initializer(익명의 메모리에 적합한 초기화 프로그램).
      break;
    case VM_FILE:
      uninit_new(pg, va_rounded, init, type, aux, file_backed_initializer); // 가상 메모리 유형이 VM_FILE인 경우 위와 유사한 인수로 uninit_new 함수를 호출하지만 file_backed_initializer를 파일 지원 메모리의 초기화 함수로 사용합니다.
      break;
    default:
      NOT_REACHED(); // 그 목적은 안전 메커니즘 역할을 하고 'NOT_REACHED()' 매크로 다음의 코드 블록이 실행되어서는 안 된다는 코드의 개발자와 독자에게 명확한 표시를 제공하는 것입니다.
      break;
    }

    pg->writable = writable; // pg의 writable 플래그를 설정합니다
    /* TODO: Insert the page into the spt. */
    spt_insert_page(spt, pg);
    return true;
  }
err:
  return false;
}

/* Find VA from spt and return page. On error, return NULL. */
/*
  spt_find_page: spt에서 va가 있는지를 찾는 함수, hash_find() 사용

  pg_round_down: 해당 va가 속해 있는 page의 시작 주소를 얻는 함수
  hash_find: Dummy page의 빈 hash_elem을 넣어주면, va에 맞는 hash_elem을 리턴해주는 함수 (hash_elem 갱신)

  hash_find가 NULL을 리턴할 수 있으므로, 리턴 시 NULL Check
*/
struct page *
spt_find_page(struct supplemental_page_table *spt, void *va)
{
  struct page *page = NULL;
  /* TODO: Fill this function. */
  void *page_addr = pg_round_down(va);

  struct page pg;
  pg.va = page_addr;
  struct hash_elem *found = hash_find(&(spt->spt), &(pg.page_elem));
  if (found == NULL)
    return NULL;
  page = hash_entry(found, struct page, page_elem);

  return page;
}

/* Insert PAGE into spt with validation. */
bool spt_insert_page(struct supplemental_page_table *spt,
                     struct page *page)
{
  int succ = false;
  /* TODO: Fill this function. */
  if (hash_insert(&(spt->spt), &(page->page_elem)) == NULL)
    succ = true;

  return succ;
}

void spt_remove_page(struct supplemental_page_table *spt, struct page *page)
{
  if (hash_delete(&(spt->spt), &(page->page_elem)) == NULL)
    return;

  vm_dealloc_page(page);
  return;
}

/* Get the struct frame, that will be evicted. */
static struct frame *
vm_get_victim(void)
{
  struct frame *victim = NULL;
  /* TODO: The policy for eviction is up to you. */
  lock_acquire(&lru_lock);
  size_t lru_len = list_size(&lru);
  struct list_elem *tmp = list_begin(&lru);
  struct frame *tmp_frame;
  struct list_elem *next_tmp;
  for (size_t i = 0; i < lru_len; i++)
  {
    tmp_frame = list_entry(tmp, struct frame, lru_elem);
    if (pml4_is_accessed(thread_current()->pml4, tmp_frame->page->va))
    {
      pml4_set_accessed(thread_current()->pml4, tmp_frame->page->va, false);
      next_tmp = list_next(tmp);
      list_remove(tmp);
      list_push_back(&lru, tmp);
      tmp = next_tmp;
      continue;
    }
    if (victim == NULL)
    {
      victim = tmp_frame;
      next_tmp = list_next(tmp);
      list_remove(tmp);
      tmp = next_tmp;
      continue;
    }
    tmp = list_next(tmp);
  }
  if (victim == NULL)
    victim = list_entry(list_pop_front(&lru), struct frame, lru_elem);
  lock_release(&lru_lock);

  return victim;
}

/* Evict one page and return the corresponding frame.
 * Return NULL on error.*/
static struct frame *
vm_evict_frame(void)
{
  struct frame *victim = vm_get_victim();
  /* TODO: swap out the victim and return the evicted frame. */
  if (!swap_out(victim->page))
    return NULL;

  victim->page = NULL;
  memset(victim->kva, 0, PGSIZE);

  return victim;
}

/* palloc() and get frame. If there is no available page, evict the page
 * and return it. This always return valid address. That is, if the user pool
 * memory is full, this function evicts the frame to get the available memory
 * space.*/
static struct frame *
vm_get_frame(void)
{
  struct frame *frame = NULL;
  /* TODO: Fill this function. */
  void *pg_ptr = palloc_get_page(PAL_USER);
  if (pg_ptr == NULL)
  {
    return vm_evict_frame();
  }

  frame = (struct frame *)malloc(sizeof(struct frame));
  frame->kva = pg_ptr;
  frame->page = NULL;

  ASSERT(frame != NULL);
  ASSERT(frame->page == NULL);
  return frame;
}

/* Growing the stack. */
/*
  하나 이상의 anonymous 페이지를 할당하여 스택 크기를 늘립니다.
  이로써 addr은 faulted 주소(폴트가 발생하는 주소) 에서 유효한 주소가 됩니다.
  페이지를 할당할 때는 주소를 PGSIZE 기준으로 내림하세요.

  vm_stack_growth 함수는 스택의 성장을 처리하는 함수입니다. 주어진 주소(addr)를 기준으로 스택을 확장합니다.

  즉, vm_stack_growth 함수는 주어진 주소를 기준으로 스택을 확장하며,
  각 페이지마다 vm_alloc_page를 호출하여 가상 메모리 페이지를 할당하고,
  해당 페이지를 확보합니다. 이를 스택이 필요한 크기까지 반복합니다.
*/
static void
vm_stack_growth(void *addr)
{
  void *pg_addr = pg_round_down(addr); // addr을 페이지 크기로 내림하여 가장 가까운 페이지 주소(pg_addr)를 계산합니다.
  ASSERT((uintptr_t)USER_STACK - (uintptr_t)pg_addr <= (1 << 20)); // ASSERT 문을 사용하여 스택이 허용된 최대 크기를 초과하지 않는지 확인합니다. 여기서 (1 << 20)은 1MB를 나타냅니다.

  while (vm_alloc_page(VM_ANON, pg_addr, true)) // vm_alloc_page 함수를 사용하여 가상 메모리 페이지를 스택에 할당합니다. 할당이 성공하면 반복문이 실행됩니다.
  {
    struct page *pg = spt_find_page(&thread_current()->spt, pg_addr); // spt_find_page 함수를 사용하여 현재 스레드의 보조 페이지 테이블에서 pg_addr에 해당하는 페이지를 찾습니다. 이를 pg에 할당합니다.
    vm_claim_page(pg_addr);                                           // vm_claim_page 함수를 호출하여 페이지를 확보합니다. 이 함수는 페이지가 실제로 사용되고 있음을 표시하는 데 사용됩니다.
    pg_addr += PGSIZE;                                                // pg_addr을 다음 페이지로 이동시킵니다. PGSIZE는 페이지의 크기를 나타냅니다.
  }
}

/* Handle the fault on write_protected page */
static bool
vm_handle_wp(struct page *page)
{
  void *parent_kva = page->frame->kva;
  page->frame->kva = palloc_get_page(PAL_USER);

  memcpy(page->frame->kva, parent_kva, PGSIZE);
  pml4_set_page(thread_current()->pml4, page->va, page->frame->kva, page->copy_writable);

  return true;
}

/* Return true on success */
/*
  가상 메모리 시스템에서 페이지 오류를 처리합니다.

  페이지 폴트가 일어나면, 페이지 폴트 핸들러는 vm_try_handle_fault 함수에게 제어권을 넘깁니다.
  이 함수는 유효한 페이지 폴트인지를 우선 검사합니다.
  이 페이지 폴트가 유효하지 않은 페이지에 접근한 폴트라면 찐 페이지 폴트일 것입니다.
  그렇지 않고 bogus 폴트라면 당신은 페이지에서 콘텐츠를 로드하고 유저 프로그램에게 제어권을 반환해야 합니다.

  마지막으로 spt_find_page를 통해 supplemental page table을 참조하여 vm_try_handle_fault 함수를 수정해서 faulted address에 해당하는 page struct를 해결한다.
*/
bool vm_try_handle_fault(struct intr_frame *f, void *addr,
                         bool user, bool write, bool not_present) // vm_try_handle_fault가 f(인터럽트 프레임에 대한 포인터), addr(페이지 폴트를 일으키는 주소), user(부울 플래그가 사용자 모드에서 오류 발생), 'write'(오류가 쓰기 액세스의 결과인지 여부를 나타내는 부울 플래그) 및 'not_present'(폴트가 존재하지 않는 페이지로 인한 것인지 여부를 나타내는 부울 플래그)입니다.
{
  struct supplemental_page_table *spt = &thread_current()->spt; // struct supplemental_page_table 유형의 spt 포인터를 선언하고 현재 스레드에 대한 추가 페이지 테이블의 주소로 초기화합니다.
  struct page *page = NULL;
  /* TODO: Validate the fault */
  /* TODO: Your code goes here */
  if (is_kernel_vaddr(addr) && user) // 오류 주소 addr이 커널 가상 주소(is_kernel_vaddr)인지, 사용자 모드(user)에서 오류가 발생했는지 확인합니다. 두 조건이 모두 참이면 오류를 처리할 수 없음을 나타내는 '거짓'을 반환합니다.
    return false;
  // printf("TID: %d, addr: %p\n", thread_current()->tid, addr);
  page = spt_find_page(spt, addr); //  'spt_find_page' 함수를 호출하여 오류 주소 'addr'에 해당하는 추가 페이지 테이블('spt')에서 페이지 항목을 검색합니다. 결과는 page 포인터에 저장됩니다.
  if (write && !not_present && page->copy_writable && page) // 오류가 쓰기 액세스(write 플래그)로 인한 것인지, 페이지가 존재하지 않는 것으로 표시되지 않았는지(!not_present), 페이지가 기록 중 복사 쓰기 가능한지(page ->copy_writable). 이러한 조건이 충족되면 vm_handle_wp 함수를 호출하여 페이지 폴트를 처리하고 결과를 반환합니다.
  {
    // printf("not present is false\n");
    return vm_handle_wp(page);
  }

  /*
     page가 NULL인 경우를 처리하며 이는 오류 주소에 대한 추가 페이지 테이블에 페이지 항목이 없음을 나타냅니다.
  */
  if (page == NULL)
  {
    struct thread *current_thread = thread_current(); // 먼저 현재 스레드를 검색하고
    void *stack_bottom = pg_round_down(thread_current()->user_rsp); // 사용자 스택 포인터(user_rsp)를 내림하여 스택의 맨 아래(stack_bottom)를 계산합니다.
    if (write && (addr >= pg_round_down(thread_current()->user_rsp - PGSIZE)) && (addr < USER_STACK)) // 오류가 쓰기 액세스(write)로 인한 것이고 주소가 스택 증가 영역(stack_bottom - PGSIZE 및 USER_STACK 사이)에 속하는 경우 vm_stack_growth 함수를 호출하여 스택을 확장하고 반환합니다.
    {
      vm_stack_growth(addr);
      return true;
    }
    return false;
  }
  if (write && !page->writable) // 결함이 쓰기 액세스(write 플래그)로 인한 것인지 그리고 페이지가 쓰기 가능하지 않은지(!page->writable) 확인합니다.
    return false;
  // printf("page->writable : %d\n", page->writable);
  // printf("write : %d\n", write);
  // printf("EQUALS ? : %d\n", page->writable == write);
  // if (is_writable(thread_current()->pml4) && write)
  // {
  //     printf("wp\n");
  //     return vm_handle_wp(page);
  // };

  // 페이지가 유효한지(NULL이 아님)와 vm_do_claim_page 함수가 페이지를 성공적으로 클레임하는지 확인합니다.
  if (vm_do_claim_page(page)) // vm_do_claim_page가 페이지가 성공적으로 클레임되었음을 나타내는 true를 반환하면 vm_try_handle_fault 함수는 페이지 오류가 처리되었음을 나타내기 위해 true를 반환합니다.
    return true;
  return false; // 그렇지 않고 페이지를 요청할 수 없거나 page가 NULL이면 함수는 페이지 폴트를 처리할 수 없음을 나타내는 false를 반환합니다.
}

/* Free the page.
 * DO NOT MODIFY THIS FUNCTION. */
void vm_dealloc_page(struct page *page)
{
  destroy(page);
  free(page);
}

/* Claim the page that allocate on VA. */
bool vm_claim_page(void *va)
{
  struct page *page = NULL;
  /* TODO: Fill this function */
  page = spt_find_page(&thread_current()->spt, va);
  if (page == NULL)
  {
    // there is no such page to accomodate va
    return false;
  }

  return vm_do_claim_page(page);
}

/* Claim the PAGE and set up the mmu. */
static bool
vm_do_claim_page(struct page *page)
{
  struct frame *frame = vm_get_frame();

  if (frame == NULL)
    return false;

  /* Set links */
  frame->page = page;
  page->frame = frame;

  /* TODO: Insert page table entry to map page's VA to frame's PA. */
  struct thread *t = thread_current();
  lock_acquire(&lru_lock);
  list_push_back(&lru, &(frame->lru_elem));
  lock_release(&lru_lock);

  if (pml4_set_page(t->pml4, page->va, frame->kva, page->writable) == false)
    return false;

  return swap_in(page, frame->kva);
}

static uint64_t spt_hash_func(const struct hash_elem *e, void *aux)
{
  const struct page *pg = hash_entry(e, struct page, page_elem);
  return hash_int(pg->va);
}

static bool spt_less_func(const struct hash_elem *a, const struct hash_elem *b)
{
  const struct page *pg_a = hash_entry(a, struct page, page_elem);
  const struct page *pg_b = hash_entry(b, struct page, page_elem);
  return pg_a->va < pg_b->va;
}

/* Initialize new supplemental page table */
void supplemental_page_table_init(struct supplemental_page_table *spt)
{
  hash_init(&(spt->spt), spt_hash_func, spt_less_func, NULL);
}

/* Copy supplemental page table from src to dst */
/*
  src부터 dst까지 supplemental page table를 복사하세요.
  이것은 자식이 부모의 실행 context를 상속할 필요가 있을 때 사용됩니다.(예 - fork()).
  src의 supplemental page table를 반복하면서 dst의 supplemental page table의 엔트리의 정확한 복사본을 만드세요.
  당신은 초기화되지않은(uninit) 페이지를 할당하고 그것들을 바로 요청할 필요가 있을 것입니다.

  supplemental_page_table_copy 기능은 소스 추가 페이지 테이블(src)의 내용을 대상 추가 페이지 테이블(dst)로 복사하는 역할을 합니다
*/
bool supplemental_page_table_copy(struct supplemental_page_table *dst,
                                  struct supplemental_page_table *src)
{
  
  struct hash_iterator iter; // 소스 페이지 테이블의 해시 테이블을 반복하도록 hash_iterator 구조가 초기화됩니다.
  hash_first(&iter, &(src->spt)); //  hash_first 함수는 이터레이터를 해시 테이블의 시작 부분으로 설정하는 데 사용됩니다.
  while (hash_next(&iter))        // 이 루프는 반복자를 다음 항목으로 이동시키는 hash_next 함수를 사용하여 소스 페이지 테이블의 해시 테이블에 있는 각 항목을 반복합니다.
  {
    struct page *tmp = hash_entry(hash_cur(&iter), struct page, page_elem); // 루프 내에서 임시 struct page 포인터 tmp는 hash_cur 및 hash_entry 매크로를 사용하여 현재 페이지 항목에 할당됩니다.
    struct page *cpy = NULL;                                                // 또 다른 struct page 포인터 cpy는 복사된 페이지 항목을 보유하기 위해 NULL로 초기화됩니다.
    // printf("curr_type: %d, parent_va: %p, aux: %p\n", VM_TYPE(tmp->operations->type), tmp->va, tmp->uninit.aux);

    // switch 문은 다양한 유형의 페이지를 처리하는 데 사용됩니다. 여기서 초기화되지 않은 페이지(VM_UNINIT 유형)를 만나면 case VM_UNINIT: 블록 내부의 코드가 실행됩니다.
    switch (VM_TYPE(tmp->operations->type))
    {
    case VM_UNINIT:
      // printf("tmp->uninit.type: %d, va: %p, aux: %p\n", tmp->uninit.type, tmp->va, tmp->uninit.aux);
      if (VM_TYPE(tmp->uninit.type) == VM_ANON) // VM_UNINIT 사례 내에서 코드는 초기화되지 않은 페이지가 VM_ANON 유형인지 확인합니다.
      {
        struct load_segment_aux *info = (struct load_segment_aux *)malloc(sizeof(struct load_segment_aux)); // 초기화되지 않은 페이지가 VM_ANON 유형이면 struct load_segment_aux 포인터 info에 메모리가 할당되고
        memcpy(info, tmp->uninit.aux, sizeof(struct load_segment_aux));                                     // tmp->uninit.aux의 내용이 memcpy를 사용하여 info에 복사됩니다.

        info->file = file_duplicate(info->file); // file_duplicate 기능은 info->file과 관련된 파일의 복제본을 생성하는 데 사용됩니다.

        vm_alloc_page_with_initializer(tmp->uninit.type, tmp->va, tmp->writable, tmp->uninit.init, (void *)info); // 그런 다음 vm_alloc_page_with_initializer가 호출되어 원본 페이지와 동일한 유형, 가상 주소, 쓰기 가능성 및 이니셜라이저를 가진 대상 페이지 테이블(dst)에 대한 가상 메모리 페이지를 할당합니다.
      }
      break;
    case VM_ANON: // VM_ANON 사례 내에서 코드는 익명 페이지를 처리합니다.
      // printf("VMANON\n");
      vm_alloc_page(tmp->operations->type, tmp->va, tmp->writable); // 대상 페이지 테이블(dst)에는 소스 페이지와 유형, 가상 주소 및 쓰기 가능성이 동일한 가상 메모리 페이지가 할당됩니다.
      cpy = spt_find_page(dst, tmp->va);                            // 그런 다음 spt_find_page 기능을 사용하여 대상 페이지 테이블에서 해당 페이지 항목을 찾습니다.

      // printf("child va : %p, type: %d\n", cpy->va, cpy->operations->type);

      if (cpy == NULL)
      {
        return false;
      }

      cpy->copy_writable = tmp->writable; // cpy->copy_writable을 tmp->writable의 값으로 설정합니다.
      struct frame *cpy_frame = malloc(sizeof(struct frame)); // struct frame 포인터인 cpy_frame에 메모리를 할당합니다.
      cpy->frame = cpy_frame;                                 // cpy_frame을 cpy->frame에 할당합니다.
      cpy_frame->page = cpy;
      // memcpy ?
      cpy_frame->kva = tmp->frame->kva; // tmp->frame->kva의 값을 cpy_frame->kva에 할당합니다.

      // LRU(Least Recently Used) 리스트를 관리하는 일부 작업을 수행합니다.
      struct thread *t = thread_current();
      lock_acquire(&lru_lock);
      list_push_back(&lru, &cpy_frame->lru_elem);
      lock_release(&lru_lock);

      if (pml4_set_page(t->pml4, cpy->va, cpy_frame->kva, 0) == false) // 현재 스레드의 페이지 테이블에 페이지 매핑을 설정하기 위해 pml4_set_page를 호출합니다.
      {
        // printf("child set page flase \n");
        return false;
      }
      swap_in(cpy, cpy_frame->kva); // 페이지가 이전에 스왑 아웃된 경우 swap_in을 호출하여 페이지를 물리 메모리로 가져옵니다.
      // pml4_clear_page(t->pml4, tmp->va);
      // pml4_destroy(t->pml4);
      // if (pml4_set_page(t->pml4, tmp->va, tmp->frame->kva, 0) == false)
      // {
      //   // printf("parent set page flase \n");
      //   return false;
      // }

      // printf("all pass \n");

      // cow - vm_do_claim_page가 페이지를 할당받으니 주석
      // if (vm_do_claim_page(cpy) == false)
      // {
      //     return false;
      // }
      // cow
      // memcpy(cpy->frame->kva, tmp->frame->kva, PGSIZE);
      break;
    case VM_FILE: // 페이지가 VM_FILE 유형인 경우, 아무 작업도 수행하지 않습니다.
      break;
    default:
      break;
    }
  }
  return true;
}

static void spt_destroy_func(struct hash_elem *e, void *aux)
{
  const struct page *pg = hash_entry(e, struct page, page_elem);
  vm_dealloc_page(pg);
}

/* Free the resource hold by the supplemental page table */
/*
  supplemental page table에 의해 유지되던 모든 자원들을 free합니다.
  이 함수는 process가 exit할 때(userprog/process.c의 process_exit()) 호출됩니다.
  당신은 페이지 엔트리를 반복하면서 테이블의 페이지에 destroy(page)를 호출하여야 합니다.
  당신은 이 함수에서 실제 페이지 테이블(pml4)와 물리 주소(palloc된 메모리)에 대해 걱정할 필요가 없습니다.
  supplemental page table이 정리되어지고 나서, 호출자가 그것들을 정리할 것입니다.
*/
void supplemental_page_table_kill(struct supplemental_page_table *spt)
{
  /* TODO: Destroy all the supplemental_page_table hold by thread */
  lock_acquire(&kill_lock);
  hash_destroy(&(spt->spt), spt_destroy_func);
  lock_release(&kill_lock);

  /* TODO: writeback all the modified contents to the storage. */
}
