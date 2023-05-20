/* file.c: Implementation of memory backed file object (mmaped object). */

#include "threads/mmu.h"
#include "vm/vm.h"

static bool file_backed_swap_in(struct page *page, void *kva);
static bool file_backed_swap_out(struct page *page);
static void file_backed_destroy(struct page *page);

/* DO NOT MODIFY this struct */
static const struct page_operations file_ops = {
    .swap_in = file_backed_swap_in,
    .swap_out = file_backed_swap_out,
    .destroy = file_backed_destroy,
    .type = VM_FILE,
};

extern struct lock filesys_lock;
extern struct lock lru_lock;

/* The initializer of file vm */
void vm_file_init(void)
{
}

/* Initialize the file backed page */
bool file_backed_initializer(struct page *page, enum vm_type type, void *kva)
{
    /* Set up the handler */
    page->operations = &file_ops;

    struct file_page *file_page = &page->file;
}

/* Swap in the page by read contents from the file. */
/*
    파일에서 콘텐츠를 읽어 kva 페이지에서 swap in합니다. 파일 시스템과 동기화해야 합니다.
*/
static bool
file_backed_swap_in(struct page *page, void *kva)
{
    // printf("file_backed_swap_in\n");
    struct file_page *file_page = &page->file; //  struct file_page 유형의 file_page 포인터를 생성하고 page 구조의 file 필드를 가리키도록 초기화합니다. file 필드에는 파일 지원 페이지에 특정한 정보가 포함되어 있습니다.

    lock_acquire(&filesys_lock); // filesys_lock을 획득하여 파일 시스템에 대한 액세스를 동기화하여 파일 작업에 대한 독점 액세스를 보장합니다.

    /*
        오프셋 file_page->에서 시작하여 페이지와 관련된 파일에서 데이터를 읽습니다.
        ofs이고 크기는 file_page->page_read_bytes입니다. 데이터는 kva로 지정된 물리적 메모리 위치로 읽혀집니다.
        file_read_at() 함수는 파일에서 실제 읽기를 수행합니다.
    */
    off_t size = file_read_at(file_page->file, kva, (off_t)file_page->page_read_bytes, file_page->ofs);
    lock_release(&filesys_lock); // 파일에서 데이터를 읽은 후 filesys_lock을 해제합니다.

    if (size != file_page->page_read_bytes) // 파일에서 읽은 데이터의 크기가 file_page->page_read_bytes와 같지 않으면 오류 또는 불완전한 읽기 작업을 나타냅니다. 이러한 경우 함수는 실패를 나타내기 위해 'false'를 반환합니다.
        return false;

    memset(kva + file_page->page_read_bytes, 0, file_page->page_zero_bytes); // kva + file_page->page_read_bytes부터 시작하여 물리적 메모리 범위의 나머지 바이트를 0으로 채웁니다. 페이지의 초기화되지 않은 부분이 제대로 초기화되었는지 확인하는 데 필요합니다.

    return true;
}

/* Swap out the page by writeback contents to the file. */

/*
    내용을 다시 파일에 기록하여 swap out합니다. 먼저 페이지가 dirty  인지 확인하는 것이 좋습니다.
    더럽지 않으면 파일의 내용을 수정할 필요가 없습니다. 페이지를 교체한 후에는 페이지의 더티 비트를 꺼야 합니다.
*/
static bool
file_backed_swap_out(struct page *page)
{
    // printf("file_backed_swap_out\n");
    struct file_page *file_page = &page->file; // struct file_page 유형의 file_page 포인터를 생성하고 page 구조의 file 필드를 가리키도록 초기화합니다. file 필드에는 파일 지원 페이지에 특정한 정보가 포함되어 있습니다.
    struct thread *curr_thread = thread_current(); // struct thread 유형의 curr_thread 포인터를 생성하고 현재 스레드를 가리키도록 초기화합니다.

    if (pml4_is_dirty(curr_thread->pml4, page->va)) // 가상 주소 page->에 대한 페이지 테이블 항목의 더티 비트를 비교하여 페이지가 수정되었는지(dirty) 확인합니다. va. 페이지가 더티하면 실제 메모리의 페이지 내용이 수정되었으며 파일에 다시 기록해야 함을 나타냅니다.
    {
        lock_acquire(&filesys_lock); // filesys_lock을 획득하여 파일 시스템에 대한 액세스를 동기화하여 파일 작업에 대한 독점 액세스를 보장합니다.
        file_write_at(file_page->file, page->va, file_page->page_read_bytes, file_page->ofs); // 가상 주소 page->va의 페이지 내용을 관련 파일에 씁니다. 오프셋 file_page->ofs에서 시작합니다. 기록된 데이터의 크기는 file_page->page_read_bytes입니다. file_write_at() 함수는 파일에 실제 쓰기를 수행합니다.
        lock_release(&filesys_lock);                                                          // 파일에 데이터를 쓴 후 이 줄은 filesys_lock을 해제합니다.

        pml4_set_dirty(curr_thread->pml4, page->va, false); // 가상 주소 page->va에 대한 페이지 테이블 항목의 더티 비트를 거짓으로 설정하여 페이지가 물리적 메모리는 더 이상 더럽지 않습니다.
    }
    pml4_clear_page(curr_thread->pml4, page->va); // 현재 스레드의 페이지 테이블에서 가상 주소 page->va에 해당하는 페이지 테이블 항목을 지웁니다. 이는 페이지가 더 이상 존재하지 않음을 나타냅니다. 물리적 메모리 프레임 간의 매핑이 효과적으로 제거됩니다.
    page->frame = NULL;                           // page 구조의 frame 필드를 NULL로 설정하여 페이지가 더 이상 물리적 메모리 프레임과 연결되지 않음을 나타냅니다.

    return true;
}

/* Destory the file backed page. PAGE will be freed by the caller. */
/*
    file_backed_destroy() 함수는 가상 메모리 하위 시스템에서 사용되는 도우미 함수입니다.
    그 목적은 파일 지원 페이지를 파괴하고 관련 리소스를 해제하는 것입니다.
*/
static void
file_backed_destroy(struct page *page)
{
    struct file_page *file_page = &page->file;
    list_remove(&(file_page->file_elem)); // 파일 지원 페이지 목록 내에서 페이지를 유지하는 데 사용되는 file_elem 목록 요소는 list_remove()를 사용하여 포함 목록에서 제거됩니다.
    if (page->frame != NULL)              // 페이지에 할당된 해당 프레임이 있는 경우(현재 물리적 메모리에 있음을 의미)
    {
        lock_acquire(&lru_lock);               // 최근에 가장 적게 사용된 목록에 대한 배타적 액세스를 보장하기 위해 'lru_lock'을 획득합니다.
        list_remove(&(page->frame->lru_elem)); // 가장 최근에 사용되지 않은 목록 내에서 페이지를 유지하는 데 사용되는 lru_elem 목록 요소는 list_remove()를 사용하여 포함 목록에서 제거됩니다.
        lock_release(&lru_lock);
        free(page->frame); // 페이지의 프레임은 free()를 사용하여 해제됩니다.
    }
}

/*
    lazy_mmap() 함수는 운영 체제에서 메모리 매핑(mmap) 중에 사용되는 도우미 함수입니다.
    파일의 데이터로 매핑된 영역의 페이지를 느리게 채우는 역할을 합니다.

    lazy_mmap() 함수는 파일의 데이터로 매핑된 영역의 페이지를 채우기 위해 메모리 매핑 중에 호출됩니다.
    파일에서 필요한 바이트 수를 읽고 페이지 구조의 파일 관련 필드를 초기화합니다.
    읽기 작업이 실패하면 페이지 할당을 해제하고 더티 비트를 'false'로 설정하고 'false'를 반환합니다.
    그렇지 않으면 'true'를 반환하여 성공적인 지연 매핑을 나타냅니다.
*/
static bool
lazy_mmap(struct page *page, void *aux)
{
    // // 부울 변수 success와 struct mmap_aux 유형의 포인터 info를 선언하여 보조 데이터를 보유합니다.
    bool success = true;
    struct mmap_aux *info = (struct mmap_aux *)aux;
    list_push_back(&(thread_current()->mmap_list), &(page->file.file_elem)); // page 구조의 file_elem 멤버를 현재 스레드의 mmap_list로 푸시하여 매핑된 파일 목록을 유지합니다.

    lock_acquire(&filesys_lock); // 파일 시스템에 대한 독점 액세스를 보장하기 위해 filesys_lock을 획득하고
    off_t read = file_read_at(info->file, page->va, (off_t)info->page_read_bytes, info->ofs); // 가상 주소 page->va의 info->file에서 info->page_read_bytes 바이트 수를 info->page_read_bytes 오프셋으로 읽습니다. 읽은 바이트 수는 read 변수에 저장됩니다.
    lock_release(&filesys_lock);                                                              // filesys_lock을 해제합니다.
    if (read != (off_t)info->page_read_bytes) // 읽은 바이트 수(read)가 info->page_read_bytes와 같지 않으면 예상 바이트 수를 읽지 못했음을 나타내며 page 할당을 해제하고 success를 false로 설정합니다.
    {
        vm_dealloc_page(page);
        success = false;
    }
    else
    {
        /*
            읽기 작업이 성공하면 info 보조 데이터의 정보로 page 구조의 file 관련 필드를 초기화합니다.
            page->file, page->file.file, page->file.start, page->file.length, page->file.ofs, 에 대한 적절한 값을 설정합니다.
            page->file.page_read_bytes 및 page->file.page_zero_bytes.
        */
        memset((page->va) + info->page_read_bytes, 0, info->page_zero_bytes);
        page->file.page = page;
        page->file.file = info->file;
        page->file.start = info->start;
        page->file.length = info->length;
        page->file.ofs = info->ofs;
        page->file.page_read_bytes = info->page_read_bytes;
        page->file.page_zero_bytes = info->page_zero_bytes;
    }
    free(aux); // 보조 데이터 aux에 할당된 메모리를 해제합니다.
    pml4_set_dirty(thread_current()->pml4, page->va, false); // 페이지가 수정되지 않았음을 나타내기 위해 pml4_set_dirty()를 사용하여 페이지의 더티 비트를 false로 설정합니다.
    return success;                                          // 지연 매핑이 성공했는지('true') 아닌지('false') 나타내는 'success' 값을 반환합니다.
}

/* Do the mmap */
/*
    mmap :
    파일 디스크립터 fd로 오픈한 파일을 offset byte 위치에서부터 시작해 length 바이트 크기만큼 읽어들여 addr에 위치한 프로세스 가상 주소 공간에 매핑한다.
    전체 파일은 페이지 단위로 나뉘어 연속적인 가상 주소 페이지에 매핑된다. 즉, mmap()은 메모리를 페이지 단위로 할당받는 시스템 콜이다.

    do_mmap() 함수는 운영 체제에서 mmap() 시스템 호출을 처리하는 데 사용됩니다. 파일을 프로세스의 가상 메모리에 매핑합니다.

    do_mmap()은 실질적으로 가상 페이지를 할당해주는 함수이다. 
    인자로 받은 addr부터 시작하는 연속적인 유저 가상 메모리 공간에 페이지를 생성해 file의 offset부터 length에 해당하는 크기만큼 파일의 정보를 각 페이지마다 저장한다.
    프로세스가 이 페이지에 접근해서 page fault가 뜨면 물리 프레임과 매핑(이때 claim을 사용한다)해 디스크에서 파일 데이터를 프레임에 복사한다.
*/
void *
do_mmap(void *addr, size_t length, int writable,
        struct file *file, off_t offset)
{
    struct file *reopen_file = file_reopen(file); // file_reopen() 함수가 호출되어 파일을 다시 열어 여전히 액세스할 수 있는지 확인합니다.

    if (reopen_file == NULL) // 다시 열기에 실패하면 오류를 나타내는 NULL이 반환됩니다.
    {
        return NULL;
    }

    // struct mmap_aux *aux_list[length / PGSIZE + 1];
    int i = 0;

    size_t read_bytes = length;
    size_t zero_bytes = PGSIZE - length % PGSIZE;
    off_t dynamic_ofs = offset;
    void *upage = addr;
    while (read_bytes > 0 || zero_bytes > 0) // 매핑 페이지를 반복하기 위해 루프가 시작됩니다. 모든 read_bytes 및 zero_bytes가 처리될 때까지 계속됩니다.
    {
        size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE; // page_read_bytes 변수는 나머지 read_bytes와 페이지 크기(PGSIZE) 사이의 작은 값으로 설정됩니다. 이 페이지에 대해 파일에서 읽을 바이트 수를 결정합니다.
        size_t page_zero_bytes = PGSIZE - page_read_bytes;                  // page_zero_bytes 변수는 page_read_bytes 이후 페이지의 남은 공간으로 설정됩니다. 0으로 초기화해야 하는 바이트 수를 나타냅니다.

        /*
             struct mmap_aux 포인터 aux가 생성되고 reopen_file, addr, length, offset, page_read_bytes 및 page_zero_bytes를 포함하여 매핑의 이 페이지에 대한 관련 정보로 초기화됩니다.
        */
        struct mmap_aux *aux = (struct mmap_aux *)malloc(sizeof(struct mmap_aux));
        aux->file = reopen_file;
        aux->start = addr;
        aux->length = length;
        aux->ofs = dynamic_ofs;
        aux->page_read_bytes = page_read_bytes;
        aux->page_zero_bytes = page_zero_bytes;
        // aux_list[i] = aux;

        if (!vm_alloc_page_with_initializer(VM_FILE, upage,
                                            writable, lazy_mmap, (void *)aux)) // vm_alloc_page_with_initializer() 함수를 호출하여 가상 메모리에 파일 매핑을 위한 페이지를 할당합니다. 페이지는 lazy_mmap 함수와 aux 포인터를 인수로 사용하여 초기화됩니다.
        {
            file_close(reopen_file); // 오류를 나타내는 할당에 실패하면 reopen_file이 닫히고 NULL이 반환됩니다.
            // for (int j = 0; j <= i; j++)
            //     free(aux_list[j]);
            return NULL;
        }

        /*
            카운터 및 포인터(read_bytes, zero_bytes, upage, dynamic_ofs)는 다음 페이지 반복을 위해 업데이트됩니다.
        */
        read_bytes -= page_read_bytes;
        zero_bytes -= page_zero_bytes;
        upage += PGSIZE;
        dynamic_ofs += PGSIZE;
        i++;
    }

    return addr;
}

/* Do the munmap */
/*
    do_munmap() 함수는 운영 체제에서 munmap() 시스템 호출을 처리하는 데 사용됩니다. 프로세스의 가상 메모리에서 이전에 매핑된 파일을 매핑 해제합니다.

    파일을 닫거나 제거해도 해당 매핑이 매핑 해제되지 않습니다. 생성된 매핑은 Unix 규칙에 따라 munmap이 호출되거나 프로세스가 종료될 때까지 유효합니다.

    do_munmap() 함수는 이전에 매핑된 파일의 페이지를 반복하고, 필요한 경우 수정된 페이지를 파일에 다시 쓰고, 추가 페이지 테이블에서 페이지를 제거하고, 할당을 해제하여 munmap() 시스템 호출을 처리합니다.
    가상 메모리에서 해당 파일을 닫고 관련 파일을 닫습니다.

    memory unmapping을 실행한다. 즉, 페이지에 연결되어 있는 물리 프레임과의 연결을 끊어준다.
    유저 가상 메모리의 시작 주소 addr부터 연속으로 나열된 페이지 모두를 매핑 해제한다.
    이때 페이지의 Dirty bit이 1인 페이지는 매핑 해제 전에 변경 사항을 디스크 파일에 업데이트해줘야 한다.
    file_backed_swap_out()과 동일한 방식.
*/
void do_munmap(void *addr)
{
    struct thread *curr_thread = thread_current();
    struct page *pg = spt_find_page(&(curr_thread->spt), addr); // spt_find_page() 함수가 호출되어 주어진 addr과 연관된 보충 페이지 테이블(spt)에서 페이지를 찾습니다. 결과 pg 변수는 매핑을 해제해야 하는 페이지를 나타냅니다.
    size_t length = pg->file.length;                            // length 변수에는 pg->file.length에서 검색된 매핑된 파일의 길이가 할당됩니다.
    struct file *file = pg->file.file;                          // file 변수에는 pg->file.file에서 검색된 매핑된 페이지와 관련된 파일 포인터가 할당됩니다.

    void *tmp;
    size_t pivot = 0;
    while (pivot < length) // 루프가 시작되어 매핑된 영역의 페이지를 반복합니다. 'pivot'이 매핑의 'length'에 도달할 때까지 계속됩니다.
    {
        pg = spt_find_page(&(curr_thread->spt), addr); // 각 반복 내에서 유효성을 보장하기 위해 현재 'addr'과 연결된 페이지를 다시 찾습니다.
        if (pml4_is_dirty(curr_thread->pml4, addr))    // 페이지가 내용이 변경되었음을 의미하는 더티(수정됨)로 표시되면 코드가 블록에 들어갑니다.
        {
            lock_acquire(&filesys_lock); // 파일 시스템에 대한 독점 액세스를 보장하기 위해 filesys_lock을 획득한 다음
            // file_write_at : 물리 프레임에 변경된 데이터를 다시 디스크 파일에 업데이트해주는 함수. buffer에 있는 데이터 사이즈 만큼, file의 file_ofs부터 써준다.
            file_write_at(file, addr, pg->file.page_read_bytes, pg->file.ofs); // file_write_at()를 사용하여 페이지 내용을 파일에 씁니다.
            lock_release(&filesys_lock);
        }

        hash_delete(&(curr_thread->spt), &(pg->page_elem)); // hash_delete()를 사용하여 해시 테이블에서 페이지를 삭제하여 추가 페이지 테이블에서 페이지를 제거합니다.
        spt_remove_page(&curr_thread->spt, pg);             // 해당 페이지는 프로세스의 추가 페이지 테이블(spt_remove_page())에서도 제거됩니다.
        vm_dealloc_page(pg);                                // vm_dealloc_page()를 사용하여 페이지가 가상 메모리에서 할당 해제됩니다.

        // addr 및 pivot은 다음 페이지로 이동하기 위해 PGSIZE(페이지 크기)만큼 증가합니다.
        addr += PGSIZE;
        pivot += PGSIZE;
    }
    file_close(file); // 모든 페이지의 매핑이 해제되면 file_close()를 사용하여 연결된 파일을 닫습니다.
}
