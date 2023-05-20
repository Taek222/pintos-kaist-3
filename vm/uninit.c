/* uninit.c: Implementation of uninitialized page.
 *
 * All of the pages are born as uninit page. When the first page fault occurs,
 * the handler chain calls uninit_initialize (page->operations.swap_in).
 * The uninit_initialize function transmutes the page into the specific page
 * object (anon, file, page_cache), by initializing the page object,and calls
 * initialization callback that passed from vm_alloc_page_with_initializer
 * function.
 * */

#include "vm/vm.h"
#include "vm/uninit.h"

static bool uninit_initialize(struct page *page, void *kva);
static void uninit_destroy(struct page *page);

/* DO NOT MODIFY this struct */
static const struct page_operations uninit_ops = {
		.swap_in = uninit_initialize,
		.swap_out = NULL,
		.destroy = uninit_destroy,
		.type = VM_UNINIT,
};

/* DO NOT MODIFY this function */
void uninit_new(struct page *page, void *va, vm_initializer *init,
								enum vm_type type, void *aux,
								bool (*initializer)(struct page *, enum vm_type, void *))
{
	ASSERT(page != NULL);

	*page = (struct page){
			.operations = &uninit_ops,
			.va = va,
			.frame = NULL, /* no frame for now */
			.uninit = (struct uninit_page){
					.init = init,
					.type = type,
					.aux = aux,
					.page_initializer = initializer,
			}};
}

/* Initalize the page on first fault */
/*
	처음으로 폴트가 발생한 페이지를 초기화 합니다. 먼저 uninit 페이지의 멤버변수인 vm_initializer와 aux를 가져온 후,  page_initializer를 함수포인터로 호출합니다.
	
	유저 프로그램이 실행될 때, 지연 로딩으로 인해 콘텐츠가 아직 로드되지 않은 페이지에 접근하게 되면 페이지 폴트가 일어나게 됩니다.
	이 페이지 폴트를 처리하는 과정에서 uninit_initialize 을 호출하고 이전에 당신이 세팅해 놓은 초기화 함수를 호출합니다.

	프로세스가 처음 만들어진(UNINIT)페이지에 처음으로 접근할 때 page fault가 발생한다.
	그러면 page fault handler는 해당 페이지를 디스크에서 프레임으로 swap-in하는데,
	UNINIT type일 때의 swap_in 함수가 바로 이 함수이다.
	즉, UNINIT 페이지 멤버를 초기화해줌으로써 페이지 타입을 인자로 주어진 타입(ANON, FILE, PAGE_CACHE)로 변환시켜준다.
	여기서 만약 segment도 load되지 않은 상태라면 lazy load segment도 진행한다.
*/
static bool
uninit_initialize(struct page *page, void *kva) // uninit_initialize는 가상 메모리에서 초기화되지 않은 페이지를 초기화하는 역할을 합니다.
{
	struct uninit_page *uninit = &page->uninit; // struct uninit_page 유형의 uninit 포인터를 선언하고 struct page 내의 uninit 필드 주소를 할당합니다. 이렇게 하면 초기화되지 않은 페이지의 속성과 데이터에 더 쉽게 액세스할 수 있습니다.

	/* Fetch first, page_initialize may overwrite the values */
	// uninit 구조에서 init 및 aux 필드의 값을 검색하여 로컬 변수에 할당합니다.
	// 이러한 필드는 초기화되지 않은 페이지에 특정한 초기화 함수 및 보조 데이터를 저장합니다.
	vm_initializer *init = uninit->init;
	void *aux = uninit->aux;

	/* TODO: You may need to fix this function. */
	return uninit->page_initializer(page, uninit->type, kva) &&
				 (init ? init(page, aux) : true);
}

/* Free the resources hold by uninit_page. Although most of pages are transmuted
 * to other page objects, it is possible to have uninit pages when the process
 * exit, which are never referenced during the execution.
 * PAGE will be freed by the caller. */
/* uninit_page가 보유한 리소스를 해제합니다. 대부분의 페이지는 다른 페이지 객체로
 * 다른 페이지 객체로 변환되지만, 프로세스가 실행 중에 참조되지 않는 프로세스가 종료될 때
 * 실행 중에 참조되지 않는 페이지가 있을 수 있습니다.
 * 호출자에 의해 페이지가 해제됩니다. */
static void
uninit_destroy(struct page *page)
{
	struct uninit_page *uninit UNUSED = &page->uninit;
	/* TODO: Fill this function.
	 * TODO: If you don't have anything to do, just return. */
}
