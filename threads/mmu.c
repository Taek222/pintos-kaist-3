#include "threads/mmu.h"

#include <stdbool.h>
#include <stddef.h>
#include <string.h>

#include "intrinsic.h"
#include "threads/init.h"
#include "threads/palloc.h"
#include "threads/pte.h"
#include "threads/thread.h"

static uint64_t *
pgdir_walk(uint64_t *pdp, const uint64_t va, int create) {
    int idx = PDX(va);
    if (pdp) {
        uint64_t *pte = (uint64_t *)pdp[idx];
        if (!((uint64_t)pte & PTE_P)) {
            if (create) {
                uint64_t *new_page = palloc_get_page(PAL_ZERO);
                if (new_page)
                    pdp[idx] = vtop(new_page) | PTE_U | PTE_W | PTE_P;
                else
                    return NULL;
            } else
                return NULL;
        }
        return (uint64_t *)ptov(PTE_ADDR(pdp[idx]) + 8 * PTX(va));
    }
    return NULL;
}

static uint64_t *
pdpe_walk(uint64_t *pdpe, const uint64_t va, int create) {
    uint64_t *pte = NULL;
    int idx = PDPE(va);
    int allocated = 0;
    if (pdpe) {
        uint64_t *pde = (uint64_t *)pdpe[idx];
        if (!((uint64_t)pde & PTE_P)) {
            if (create) {
                uint64_t *new_page = palloc_get_page(PAL_ZERO);
                if (new_page) {
                    pdpe[idx] = vtop(new_page) | PTE_U | PTE_W | PTE_P;
                    allocated = 1;
                } else
                    return NULL;
            } else
                return NULL;
        }
        pte = pgdir_walk(ptov(PTE_ADDR(pdpe[idx])), va, create);
    }
    if (pte == NULL && allocated) {
        palloc_free_page((void *)ptov(PTE_ADDR(pdpe[idx])));
        pdpe[idx] = 0;
    }
    return pte;
}

/* Returns the address of the page table entry for virtual
 * address VADDR in page map level 4, pml4.
 * If PML4E does not have a page table for VADDR, behavior depends
 * on CREATE.  If CREATE is true, then a new page table is
 * created and a pointer into it is returned.  Otherwise, a null
 * pointer is returned. */
/* 가상 페이지 테이블 항목의 주소를 반환합니다.
 * 페이지 맵 레벨 4, pml4의 주소 VADDR을 반환합니다.
 * PML4E에 VADDR에 대한 페이지 테이블이 없는 경우, 동작은 CREATE에 따라
 * 에 따라 달라집니다.  CREATE가 참이면 새 페이지 테이블이
 * 생성되고 이에 대한 포인터가 반환됩니다.  그렇지 않으면 null
 * 포인터가 반환됩니다. */

/*
    pml4e_walk() 함수는 x86-64 페이징 계층 구조의 페이지 테이블을 탐색하고 주어진 가상 주소에 해당하는 페이지 테이블 항목(PTE)을 검색하는 데 사용됩니다.
    PML4E(Page Map Level 4 Entry)를 가상 주소(va) 및 새 페이지 테이블 항목이 존재하지 않는 경우 생성할지 여부를 나타내는 플래그 create와 함께 입력으로 사용합니다.
*/
uint64_t *
pml4e_walk(uint64_t *pml4e, const uint64_t va, int create) {
    uint64_t *pte = NULL; // 포인터 pte를 NULL로 초기화하여 결과 페이지 테이블 항목을 저장합니다.
    int idx = PML4(va);   // 주어진 가상 주소(va)에 해당하는 PML4E 항목의 인덱스를 계산합니다.
    int allocated = 0;    // 새 페이지 테이블이 할당되었는지 추적하기 위해 '할당됨' 플래그를 초기화합니다.
    if (pml4e) {
        uint64_t *pdpe = (uint64_t *)pml4e[idx]; // PML4E 항목을 uint64_t*로 변환하여 계산된 인덱스에 해당하는 PDPTE(Page Directory Pointer Table Entry)에 액세스합니다.
        if (!((uint64_t)pdpe & PTE_P)) {
            if (create)
            { // create 플래그가 설정되어 있는지 확인하십시오. 이는 존재하지 않는 경우 새 페이지 테이블 항목을 생성해야 함을 나타냅니다.
                uint64_t *new_page = palloc_get_page(PAL_ZERO); // palloc_get_page()를 사용하여 페이지 테이블에 대한 새로운 물리적 페이지를 할당합니다. PAL_ZERO 플래그는 페이지가 0이 되도록 합니다.
                if (new_page) {
                    pml4e[idx] = vtop(new_page) | PTE_U | PTE_W | PTE_P; // 새로 할당된 페이지 테이블의 물리적 주소로 PML4E 항목을 필수 플래그(사용자 액세스의 경우 PTE_U, 쓰기 권한의 경우 PTE_W, 존재 여부의 경우 PTE_P)와 함께 설정합니다.
                    allocated = 1;                                       // 새 페이지 테이블이 할당되었음을 나타내기 위해 allocated 플래그를 설정합니다.
                }
                else // 새 페이지를 할당할 수 없으면 NULL을 반환합니다.
                    return NULL;
            }
            else // PDPTE가 없고 create 플래그가 설정되지 않은 경우 NULL을 반환하여 유효한 페이지 테이블 항목이 없음을 나타냅니다.
                return NULL;
        }
        pte = pdpe_walk(ptov(PTE_ADDR(pml4e[idx])), va, create); // 반복적으로 pdpe_walk()를 호출하여 PDPTE 내에서 주어진 가상 주소에 대한 페이지 테이블 항목을 검색합니다. 가상 주소 및 'create' 플래그와 함께 PML4E 항목을 마스킹하여 얻은 페이지 테이블의 물리적 주소를 전달합니다.
    }
    if (pte == NULL && allocated) { // 결과 페이지 테이블 항목이 NULL이고 새 페이지 테이블이 할당되었는지 확인하십시오.
        palloc_free_page((void *)ptov(PTE_ADDR(pml4e[idx]))); // ptov()를 사용하여 물리적 주소를 가상 주소로 변환하여 할당된 페이지 테이블을 해제하고
        pml4e[idx] = 0;
    }
    return pte;
}

/* Creates a new page map level 4 (pml4) has mappings for kernel
 * virtual addresses, but none for user virtual addresses.
 * Returns the new page directory, or a null pointer if memory
 * allocation fails. */
uint64_t *
pml4_create(void) {
    uint64_t *pml4 = palloc_get_page(0);
    if (pml4)
        memcpy(pml4, base_pml4, PGSIZE);
    return pml4;
}

static bool
pt_for_each(uint64_t *pt, pte_for_each_func *func, void *aux,
            unsigned pml4_index, unsigned pdp_index, unsigned pdx_index) {
    for (unsigned i = 0; i < PGSIZE / sizeof(uint64_t *); i++) {
        uint64_t *pte = &pt[i];
        if (((uint64_t)*pte) & PTE_P) {
            void *va = (void *)(((uint64_t)pml4_index << PML4SHIFT) |
                                ((uint64_t)pdp_index << PDPESHIFT) |
                                ((uint64_t)pdx_index << PDXSHIFT) |
                                ((uint64_t)i << PTXSHIFT));
            if (!func(pte, va, aux))
                return false;
        }
    }
    return true;
}

static bool
pgdir_for_each(uint64_t *pdp, pte_for_each_func *func, void *aux,
               unsigned pml4_index, unsigned pdp_index) {
    for (unsigned i = 0; i < PGSIZE / sizeof(uint64_t *); i++) {
        uint64_t *pte = ptov((uint64_t *)pdp[i]);
        if (((uint64_t)pte) & PTE_P)
            if (!pt_for_each((uint64_t *)PTE_ADDR(pte), func, aux,
                             pml4_index, pdp_index, i))
                return false;
    }
    return true;
}

static bool
pdp_for_each(uint64_t *pdp,
             pte_for_each_func *func, void *aux, unsigned pml4_index) {
    for (unsigned i = 0; i < PGSIZE / sizeof(uint64_t *); i++) {
        uint64_t *pde = ptov((uint64_t *)pdp[i]);
        if (((uint64_t)pde) & PTE_P)
            if (!pgdir_for_each((uint64_t *)PTE_ADDR(pde), func,
                                aux, pml4_index, i))
                return false;
    }
    return true;
}

/* Apply FUNC to each available pte entries including kernel's. */
bool pml4_for_each(uint64_t *pml4, pte_for_each_func *func, void *aux) {
    for (unsigned i = 0; i < PGSIZE / sizeof(uint64_t *); i++) {
        uint64_t *pdpe = ptov((uint64_t *)pml4[i]);
        if (((uint64_t)pdpe) & PTE_P)
            if (!pdp_for_each((uint64_t *)PTE_ADDR(pdpe), func, aux, i))
                return false;
    }
    return true;
}

static void
pt_destroy(uint64_t *pt) {
    for (unsigned i = 0; i < PGSIZE / sizeof(uint64_t *); i++) {
        uint64_t *pte = ptov((uint64_t *)pt[i]);
        if (((uint64_t)pte) & PTE_P)
            palloc_free_page((void *)PTE_ADDR(pte));
    }
    palloc_free_page((void *)pt);
}

static void
pgdir_destroy(uint64_t *pdp) {
    for (unsigned i = 0; i < PGSIZE / sizeof(uint64_t *); i++) {
        uint64_t *pte = ptov((uint64_t *)pdp[i]);
        if (((uint64_t)pte) & PTE_P)
            pt_destroy(PTE_ADDR(pte));
    }
    palloc_free_page((void *)pdp);
}

static void
pdpe_destroy(uint64_t *pdpe) {
    for (unsigned i = 0; i < PGSIZE / sizeof(uint64_t *); i++) {
        uint64_t *pde = ptov((uint64_t *)pdpe[i]);
        if (((uint64_t)pde) & PTE_P)
            pgdir_destroy((void *)PTE_ADDR(pde));
    }
    palloc_free_page((void *)pdpe);
}

/* Destroys pml4e, freeing all the pages it references. */
void pml4_destroy(uint64_t *pml4) {
    if (pml4 == NULL)
        return;
    ASSERT(pml4 != base_pml4);

    /* if PML4 (vaddr) >= 1, it's kernel space by define. */
    uint64_t *pdpe = ptov((uint64_t *)pml4[0]);
    if (((uint64_t)pdpe) & PTE_P)
        pdpe_destroy((void *)PTE_ADDR(pdpe));
    palloc_free_page((void *)pml4);
}

/* Loads page directory PD into the CPU's page directory base
 * register. */
void pml4_activate(uint64_t *pml4) {
    lcr3(vtop(pml4 ? pml4 : base_pml4));
}

/* Looks up the physical address that corresponds to user virtual
 * address UADDR in pml4.  Returns the kernel virtual address
 * corresponding to that physical address, or a null pointer if
 * UADDR is unmapped. */
void *
pml4_get_page(uint64_t *pml4, const void *uaddr) {
    ASSERT(is_user_vaddr(uaddr));

    uint64_t *pte = pml4e_walk(pml4, (uint64_t)uaddr, 0);

    if (pte && (*pte & PTE_P))
        return ptov(PTE_ADDR(*pte)) + pg_ofs(uaddr);
    return NULL;
}

/* Adds a mapping in page map level 4 PML4 from user virtual page
 * UPAGE to the physical frame identified by kernel virtual address KPAGE.
 * UPAGE must not already be mapped. KPAGE should probably be a page obtained
 * from the user pool with palloc_get_page().
 * If WRITABLE is true, the new page is read/write;
 * otherwise it is read-only.
 * Returns true if successful, false if memory allocation
 * failed. */
bool pml4_set_page(uint64_t *pml4, void *upage, void *kpage, bool rw) {
    ASSERT(pg_ofs(upage) == 0);
    ASSERT(pg_ofs(kpage) == 0);
    ASSERT(is_user_vaddr(upage));
    ASSERT(pml4 != base_pml4);

    uint64_t *pte = pml4e_walk(pml4, (uint64_t)upage, 1);

    if (pte)
        *pte = vtop(kpage) | PTE_P | (rw ? PTE_W : 0) | PTE_U;
    return pte != NULL;
}

/* Marks user virtual page UPAGE "not present" in page
 * directory PD.  Later accesses to the page will fault.  Other
 * bits in the page table entry are preserved.
 * UPAGE need not be mapped. */
void pml4_clear_page(uint64_t *pml4, void *upage) {
    uint64_t *pte;
    ASSERT(pg_ofs(upage) == 0);
    ASSERT(is_user_vaddr(upage));

    pte = pml4e_walk(pml4, (uint64_t)upage, false);

    if (pte != NULL && (*pte & PTE_P) != 0) {
        *pte &= ~PTE_P;
        if (rcr3() == vtop(pml4))
            invlpg((uint64_t)upage);
    }
}

/* Returns true if the PTE for virtual page VPAGE in PML4 is dirty,
 * that is, if the page has been modified since the PTE was
 * installed.
 * Returns false if PML4 contains no PTE for VPAGE. */
bool pml4_is_dirty(uint64_t *pml4, const void *vpage) {
    uint64_t *pte = pml4e_walk(pml4, (uint64_t)vpage, false);
    return pte != NULL && (*pte & PTE_D) != 0;
}

/* Set the dirty bit to DIRTY in the PTE for virtual page VPAGE
 * in PML4. */
/*
    pml4_set_dirty() 함수는 PML4(페이지 맵 레벨 4) 테이블에서 페이지 테이블 항목의 더티 플래그(PTE_D)를 설정하거나 지우는 데 사용됩니다
    PML4 테이블 포인터(pml4), 가상 페이지 주소(vpage) 및 더티 플래그를 설정할지 또는 지울지 여부를 나타내는 부울 플래그(dirty)를 사용합니다.
*/
void pml4_set_dirty(uint64_t *pml4, const void *vpage, bool dirty) {
    /*
        pml4e_walk() 함수를 호출하여 PML4 테이블에서 가상 페이지 주소(vpage)에 해당하는 페이지 테이블 항목(PTE)을 검색합니다.
        'false' 플래그는 새 페이지 테이블 항목이 존재하지 않는 경우 생성되지 않아야 함을 나타냅니다. 결과 PTE는 pte 포인터에 저장됩니다.
    */
    uint64_t *pte = pml4e_walk(pml4, (uint64_t)vpage, false);
    if (pte) {
        if (dirty) // dirty 플래그가 true인지 확인하여 더티 플래그를 설정해야 함을 나타냅니다.
            *pte |= PTE_D; // pte와 PTE_D가 가리키는 값 사이에 비트 OR 연산을 수행하여 더티 플래그(PTE_D)를 설정합니다. 이렇게 하면 페이지 테이블 항목에 더티 플래그가 설정됩니다.
        else               // dirty 플래그가 false인 경우 더티 플래그를 지워야 함을 나타냅니다.
            *pte &= ~(uint32_t)PTE_D; // pte가 가리키는 값과 PTE_D의 보수 사이에 비트 AND 연산을 수행하여 더티 플래그를 지웁니다. 이렇게 하면 페이지 테이블 항목에서 더티 플래그가 지워집니다.

        /*
            제어 레지스터 CR3(rcr3() 함수를 통해 얻은 값)의 현재 값이 PML4 테이블의 물리적 주소(vtop(pml4))와 같은지 확인하십시오.
            이 조건은 수정 중인 현재 페이지 테이블이 활성 페이지 테이블인지 확인합니다.
        */
        if (rcr3() == vtop(pml4))
            invlpg((uint64_t)vpage); // invlpg() 함수를 호출하여 가상 페이지 주소(vpage)에 대한 변환 색인 버퍼(TLB) 항목을 무효화합니다. 이렇게 하면 TLB가 수정된 페이지 테이블 항목으로 업데이트됩니다. 이 함수는 페이지 테이블 항목의 더티 플래그를 설정하거나 지우고 필요한 경우 TLB를 업데이트합니다.
    }
}

/* Returns true if the PTE for virtual page VPAGE in PML4 has been
 * accessed recently, that is, between the time the PTE was
 * installed and the last time it was cleared.  Returns false if
 * PML4 contains no PTE for VPAGE. */
bool pml4_is_accessed(uint64_t *pml4, const void *vpage) {
    uint64_t *pte = pml4e_walk(pml4, (uint64_t)vpage, false);
    return pte != NULL && (*pte & PTE_A) != 0;
}

/* Sets the accessed bit to ACCESSED in the PTE for virtual page
   VPAGE in PD. */
void pml4_set_accessed(uint64_t *pml4, const void *vpage, bool accessed) {
    uint64_t *pte = pml4e_walk(pml4, (uint64_t)vpage, false);
    if (pte) {
        if (accessed)
            *pte |= PTE_A;
        else
            *pte &= ~(uint32_t)PTE_A;

        if (rcr3() == vtop(pml4))
            invlpg((uint64_t)vpage);
    }
}
