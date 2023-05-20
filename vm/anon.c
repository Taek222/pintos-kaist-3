/* anon.c: Implementation of page for non-disk image (a.k.a. anonymous page). */

#include <bitmap.h>

#include "devices/disk.h"
#include "threads/mmu.h"
#include "vm/vm.h"

/* DO NOT MODIFY BELOW LINE */
static struct disk *swap_disk;
static struct bitmap *disk_bitmap;
static struct lock bitmap_lock;
static bool anon_swap_in(struct page *page, void *kva);
static bool anon_swap_out(struct page *page);
static void anon_destroy(struct page *page);

extern struct list lru;
extern struct lock lru_lock;

/* DO NOT MODIFY this struct */
static const struct page_operations anon_ops = {
    .swap_in = anon_swap_in, 
    .swap_out = anon_swap_out,
    .destroy = anon_destroy,
    .type = VM_ANON,
};

/* Initialize the data for anonymous pages */
/*
    vm_anon_init() 함수는 가상 메모리 모듈에서 익명 메모리 관리 하위 시스템을 초기화하는 역할을 합니다.
*/
void vm_anon_init(void)
{
    /* TODO: Set up the swap_disk. */
    swap_disk = disk_get(1, 1); // 물리적 메모리에서 제거된 페이지를 저장하는 데 사용되는 스왑 디스크를 검색합니다. disk_get() 함수를 호출하여 디스크 장치의 메이저 및 마이너 번호를 나타내는 1, 1을 인수로 사용하여 디스크에 대한 핸들을 얻습니다.
    disk_bitmap = bitmap_create((size_t)disk_size(swap_disk)); // 스왑 디스크의 섹터 사용 상태를 추적하기 위해 비트맵을 생성합니다. disk_size() 함수는 스왑 디스크의 총 섹터 수를 반환한 다음 size_t로 변환하여 비트맵의 크기를 결정합니다. 비트맵을 생성하기 위해 bitmap_create() 함수가 호출됩니다.
    lock_init(&bitmap_lock);                                   //  bitmap_lock이라는 잠금을 초기화합니다. 잠금은 디스크 비트맵에 액세스하거나 수정할 때 동기화를 제공하여 동시 작업이 적절하게 직렬화되고 경쟁 조건을 방지하는 데 사용됩니다.
}

/* Initialize the file mapping */
/*
    anon_initializer : page_operations에서 익명 페이지에 대한 핸들러를 설정한다.
    현재 빈 구조체인 anon_page의 일부 정보를 업데이트해야 할 수도 있다.
    이 함수는 익명 페이지(예: VM_ANON)의 이니셜라이저로 사용된다.

    anon_initializer() 함수는 가상 메모리 하위 시스템의 익명 페이지에 대한 초기화 함수입니다.
    익명 페이지에 필요한 데이터 구조와 속성을 설정합니다.
*/
bool anon_initializer(struct page *page, enum vm_type type, void *kva)
{
    /* Set up the handler */
    page->operations = &anon_ops; // anon_ops 구조를 가리키도록 page 구조의 operations 필드를 설정합니다. anon_ops 구조에는 익명 페이지에서 수행할 수 있는 다양한 작업에 대한 함수 포인터가 포함되어 있습니다.

    struct anon_page *anon_page = &page->anon; // struct anon_page 유형의 anon_page 포인터를 생성하고 page 구조의 anon 필드를 가리키도록 초기화합니다. 'anon' 필드는 익명 페이지에 특정한 정보를 보유하는 'page' 구조 내의 하위 구조입니다.
    /* project3 */
    anon_page->sec_no = SIZE_MAX; // anon_page 구조체의 sec_no 필드는 SIZE_MAX로 설정됩니다. 이 필드는 물리적 메모리에서 제거될 때 페이지가 저장되는 스왑 디스크의 섹터 번호를 나타냅니다. 'SIZE_MAX'로 설정하면 페이지가 현재 스왑 디스크에 없음을 나타냅니다.
    anon_page->thread = thread_current(); // anon_page 구조의 thread 필드에 thread_current() 함수의 반환 값을 할당합니다. 현재 실행 중인 스레드에 대한 포인터를 저장합니다. 이 정보는 익명 페이지가 특정 스레드와 연결된 시나리오에서 유용할 수 있습니다.

    return true;
}

/* Swap in the page by read contents from the swap disk. */
/*
    스왑 디스크 데이터 내용을 읽어서 익명 페이지를(디스크에서 메모리로)  swap in합니다.
    (데이터의 위치 정보는) 스왑 아웃될때 페이지 구조체에 저장되어야 합니다. 스왑 테이블을 업데이트해야 합니다

    anon_swap_in() 함수는 익명 페이지를 스왑 디스크에서 실제 메모리로 스왑하는 역할을 합니다.

    'anon_swap_in()' 함수는 익명 페이지에서 스왑 디스크에서 물리적 메모리로 스왑합니다.
    디스크 비트맵의 섹터 가용성에 대해 필요한 검사를 수행하고, 스왑 디스크에서 페이지 데이터를 읽고,
    섹터를 사용 중인 것으로 표시하기 위해 비트맵을 업데이트하고, 스왑 인의 성공 또는 실패를 나타내는 부울 값을 반환합니다.
*/
static bool
anon_swap_in(struct page *page, void *kva)
{
    // printf("anon_swap_in\n");
    struct anon_page *anon_page = &page->anon; // struct anon_page 유형의 anon_page 포인터를 생성하고 page 구조의 anon 필드를 가리키도록 초기화합니다. 'anon' 필드에는 익명 페이지에 특정한 정보가 포함되어 있습니다.

    if (anon_page->sec_no == SIZE_MAX) //  anon_page 구조의 sec_no 필드가 SIZE_MAX와 같은지 확인합니다. 그렇다면 페이지가 현재 스왑 디스크에 없다는 의미이므로 함수는 스왑 인 작업을 수행할 수 없음을 나타내는 'false'를 반환합니다.
        return false;

    lock_acquire(&bitmap_lock); // 스왑 디스크의 섹터 가용성을 추적하는 디스크 비트맵에 대한 액세스를 동기화하기 위해 bitmap_lock을 획득합니다.
    bool check = bitmap_contains(disk_bitmap, anon_page->sec_no, 8, false); // 디스크 비트맵의 anon_page->sec_no에서 시작하는 8개 섹터 범위가 사용 가능한 것으로 표시되는지(즉, 사용하지 않음). 이 검사에는 bitmap_contains 함수가 사용됩니다.
    lock_release(&bitmap_lock);                                             // 디스크 비트맵을 확인한 후 bitmap_lock을 해제합니다.
    if (check)                                                              // check 변수가 true인 경우(범위의 섹터를 사용할 수 없음을 나타냄) 함수는 스왑 인 작업을 수행할 수 없음을 나타내기 위해 false를 반환합니다.
    {
        return false;
    }

    /*
        for 루프로 시작하여 disk_read()로 끝나는 다음 줄은 스왑 디스크에서 실제 메모리로 페이지를 실제로 읽습니다.
        루프는 8개 섹터 범위를 반복하고 disk_read()를 사용하여 스왑 디스크에서 각 섹터를 읽고 데이터를 물리적 메모리의 해당 위치에 복사합니다.
    */
    for (int i = 0; i < 8; i++)
    {
        disk_read(swap_disk, anon_page->sec_no + i, kva + i * DISK_SECTOR_SIZE);
    }

    lock_acquire(&bitmap_lock); // bitmap_lock을 다시 획득합니다.
    bitmap_set_multiple(disk_bitmap, anon_page->sec_no, 8, false); // 디스크 비트맵에서 anon_page->sec_no부터 시작하는 8개 섹터 범위를 사용할 수 없는(즉, 사용 중인) 것으로 표시합니다. 'false'에 해당하는 비트. 이렇게 하면 페이지가 실제 메모리에 있는 동안 섹터가 다른 목적으로 할당되지 않습니다.
    lock_release(&bitmap_lock);                                    // bitmap_lock이 해제됩니다.

    return true;
}

/* Swap out the page by writing contents to the swap disk. */
/*
    메모리에서 디스크로 내용을 복사하여 익명 페이지를 스왑 디스크로 교체합니다.
    먼저 스왑 테이블을 사용하여 디스크에서 사용 가능한 스왑 슬롯을 찾은 다음 데이터 페이지를 슬롯에 복사합니다.
    데이터의 위치는 페이지 구조체에 저장되어야 합니다. 디스크에 사용 가능한 슬롯이 더 이상 없으면 커널 패닉이 발생할 수 있습니다.

    'anon_swap_out()' 함수는 물리적 메모리에서 스왑 디스크로 익명 페이지를 스왑 아웃하는 역할을 합니다.
*/
static bool
anon_swap_out(struct page *page)
{
    // printf("anon_swap_out\n");
    struct anon_page *anon_page = &page->anon; // struct anon_page 유형의 anon_page 포인터를 생성하고 page 구조의 anon 필드를 가리키도록 초기화합니다. 'anon' 필드에는 익명 페이지에 특정한 정보가 포함되어 있습니다.

    lock_acquire(&bitmap_lock); // 스왑 디스크의 섹터 가용성을 추적하는 디스크 비트맵에 대한 액세스를 동기화하기 위해 bitmap_lock을 획득합니다.
    disk_sector_t sec_no = (disk_sector_t)bitmap_scan_and_flip(disk_bitmap, 0, 8, false); // bitmap_scan_and_flip() 함수. 찾은 범위의 시작 섹터 번호를 반환하고 섹터를 비트맵에서 사용 중인 것으로 표시합니다.
    lock_release(&bitmap_lock);                                                           // 디스크 비트맵을 수정한 후 이 줄은 bitmap_lock을 해제합니다.
    if (sec_no == BITMAP_ERROR)                                                           // sec_no 변수가 BITMAP_ERROR와 같으면 디스크 비트맵에서 8개의 연속 섹터 범위를 찾을 수 없음을 의미합니다. swap-out 작업을 수행할 수 없습니다. 이러한 경우 함수는 'false'를 반환합니다.
        return false;

    anon_page->sec_no = sec_no; // anon_page 구조의 no_sec 필드를 시작 섹터 번호 sec_no로 업데이트합니다. 이 정보는 스왑 디스크에서 페이지 위치를 추적하는 데 사용됩니다.

    /*
        for 루프로 시작하여 disk_write()로 끝나는 다음 행은 실제 메모리에서 스왑 디스크로 페이지를 실제로 쓰는 작업을 수행합니다.
        루프는 8개 섹터 범위에서 반복되며 disk_write()를 사용하여 실제 메모리에서 스왑 디스크의 각 섹터에 해당 데이터를 씁니다.
    */
    for (int i = 0; i < 8; i++)
    {
        disk_write(swap_disk, sec_no + i, page->frame->kva + i * DISK_SECTOR_SIZE);
    }

    pml4_clear_page(anon_page->thread->pml4, page->va); // 스레드 페이지 맵 레벨 4(PML4)의 페이지 테이블에서 가상 주소 page->va에 대한 항목을 지웁니다. 가상 주소와 실제 메모리 간의 매핑을 제거합니다.
    pml4_set_dirty(anon_page->thread->pml4, page->va, false); // 스레드의 PML4에 있는 가상 주소 page->va에 대한 페이지 테이블 항목의 더티 비트를  false는 페이지가 스왑 디스크에 기록되었고 더 이상 더티가 아님을 나타냅니다.
    page->frame = NULL;                                       // page 구조의 frame 필드를 NULL로 설정하여 페이지가 더 이상 물리적 프레임에 매핑되지 않음을 나타냅니다.

    return true;
}

/* Destroy the anonymous page. PAGE will be freed by the caller. */
/*
    익명 페이지에 의해 유지되던 자원들을 free시킵니다.
    당신은 명시적으로 페이지 구조체를 free시킬 필요가 없습니다.
    호출자가 수행할 겁니다.
*/
static void
anon_destroy(struct page *page)
{
    struct anon_page *anon_page = &page->anon;
    if (page->frame != NULL)
    {
        // printf("anon_destroy: %s\n", thread_current()->name);
        // printf("remove: %p, kva:%p\n", page->va, page->frame->kva);
        // printf("list_size: %d, list: %p\n", list_size(&lru), &lru);

        lock_acquire(&lru_lock);
        list_remove(&page->frame->lru_elem);
        lock_release(&lru_lock);

        // printf("anon_destroy: list: %p\n", &lru);

        // pte write bit 1 -> free
        free(page->frame);
    }
    if (anon_page->sec_no != SIZE_MAX)
        bitmap_set_multiple(disk_bitmap, anon_page->sec_no, 8, false);
}
