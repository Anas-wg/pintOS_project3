/* vm.c: Generic interface for virtual memory objects. */

#include "threads/malloc.h"
#include "vm/vm.h"
#include "threads/vaddr.h"
#include "vm/inspect.h"
#include "threads/mmu.h"
#include "userprog/process.h"

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
void hash_page_destroy(struct hash_elem *e, void *aux);

/* Create the pending page object with initializer. If you want to create a
 * page, do not create it directly and make it through this function or
 * `vm_alloc_page`. */
/* 페이지 구조체를 생성하고 적절한 초기화 함수를 설정*/
bool vm_alloc_page_with_initializer(enum vm_type type, void *upage, bool writable,
																		vm_initializer *init, void *aux)
{

	ASSERT(VM_TYPE(type) != VM_UNINIT)

	struct supplemental_page_table *spt = &thread_current()->spt;

	/* Check wheter the upage is already occupied or not. */
	if (spt_find_page(spt, upage) == NULL)
	{
		/* TODO: Create the page, fetch the initialier according to the VM type,
		 * TODO: and then create "uninit" page struct by calling uninit_new. You
		 * TODO: should modify the field after calling the uninit_new. */

		/* TODO: Insert the page into the spt. */
		// 1. 페이지 생성
		struct page *p = (struct page *)malloc(sizeof(struct page));
		// 2. 타입에 따른 초기화 함수 가져오기
		bool (*page_initializer)(struct page *, enum vm_type, void *);
		switch (VM_TYPE(type))
		{
		case VM_ANON:
			page_initializer = anon_initializer;
			break;
		case VM_FILE:
			page_initializer = file_backed_initializer;
			break;
		}
		// 3. uninit 타입의 페이지로 초기화
		// uninit_new -> uninit 타입으로 초기화해주는 함수
		uninit_new(p, upage, init, type, aux, page_initializer);

		// 4. 필드 수정
		p->writable = writable;

		// 5. 페이지 spt 추가
		return spt_insert_page(spt, p);
	}
err:
	return false;
}

/* Find VA from spt and return page. On error, return NULL. */
/*
	주어진 spt에서 주어진 va에 해당하는 struct page 정보를 탐색
*/
struct page *
spt_find_page(struct supplemental_page_table *spt UNUSED, void *va UNUSED)
{
	// struct page *page = NULL;
	struct page p_key;
	// page = malloc(sizeof(struct page));
	struct hash_elem *e;

	// va에 해당하는 hash_elem 찾기
	p_key.va = pg_round_down(va);
	e = hash_find(&spt->spt_pages, &p_key.hash_elem);

	// 있으면 e에 해당하는 페이지 반환
	return e != NULL ? hash_entry(e, struct page, hash_elem) : NULL;
}

/* Insert PAGE into spt with validation. */
/* Insert PAGE into spt with validation. */
bool spt_insert_page(struct supplemental_page_table *spt UNUSED,
										 struct page *page UNUSED)
{
	/* TODO: Fill this function. */
	return hash_insert(&spt->spt_pages, &page->hash_elem) == NULL ? true : false; // 존재하지 않을 경우에만 삽입
}

void spt_remove_page(struct supplemental_page_table *spt, struct page *page)
{
	vm_dealloc_page(page);
	return true;
}

/* Get the struct frame, that will be evicted. */
static struct frame *
vm_get_victim(void)
{
	struct frame *victim = NULL;
	/* TODO: The policy for eviction is up to you. */

	return victim;
}

/* Evict one page and return the corresponding frame.
 * Return NULL on error.*/
static struct frame *
vm_evict_frame(void)
{
	struct frame *victim UNUSED = vm_get_victim();
	/* TODO: swap out the victim and return the evicted frame. */

	return NULL;
}

/* palloc() and get frame. If there is no available page, evict the page
 * and return it. This always return valid address. That is, if the user pool
 * memory is full, this function evicts the frame to get the available memory
 * space.*/
/* 사용자 풀에서 새로운 물리 프레임 가져오기.
 * 페이지 교체 로직 추가 전까지는 실패 시 PANIC. */
static struct frame *
vm_get_frame(void)
{
	struct frame *frame = NULL;
	/* TODO: Fill this function. */
	void *kva = palloc_get_page(PAL_USER); // user pool에서 새로운 physical page를 가져온다.

	if (kva == NULL) // page 할당 실패 -> 나중에 swap_out 처리
		PANIC("todo"); // OS를 중지시키고, 소스 파일명, 라인 번호, 함수명 등의 정보와 함께 사용자 지정 메시지를 출력

	frame = calloc(1, sizeof(struct frame));
	if (frame == NULL)
	{												 // malloc 실패 처리
		palloc_free_page(kva); // 이미 할당받은 kva는 반환
		PANIC("vm_get_frame: Malloc 할당 실패");
	}
	frame->kva = kva; // 프레임 멤버 초기화
	// frame->page = NULL; // 명시적 초기화 추가

	ASSERT(frame != NULL);
	ASSERT(frame->page == NULL);
	return frame;
}

/* Growing the stack. */
static bool
vm_stack_growth(void *addr UNUSED)
{
	void *va = pg_round_down(addr);
	if (vm_alloc_page_with_initializer(VM_ANON | VM_MARKER_0, va, true, NULL, NULL))
	{
		thread_current()->rsp = va;
		return vm_claim_page(va);
	}
	return false;
}

/* Handle the fault on write_protected page */
static bool
vm_handle_wp(struct page *page UNUSED)
{
}

/* Return true on success */
bool vm_try_handle_fault(struct intr_frame *f UNUSED, void *addr UNUSED,
												 bool user UNUSED, bool write UNUSED, bool not_present UNUSED)
{
	struct supplemental_page_table *spt UNUSED = &thread_current()->spt;
	struct page *page = NULL;
	void *MAX_STACK = (USER_STACK - (1 << 20));
	if (addr == NULL || is_kernel_vaddr(addr))
		return false;

	if (not_present)
	{
		/** Project 3-Stack Growth*/
		if (page == NULL)
		{
			// 페이지가 spt에 존재하지 않는다면, 즉 아직 해당 가상 주소에 대한 매핑이 없다면,

			void *rsp = user ? pg_round_down(f->rsp) : thread_current()->rsp;
			// 만약 유저 모드라면 유저 스택 포인터(rsp)를 현재 인터럽트 프레임에서 가져오고,
			// 그렇지 않으면 (커널 모드일 경우) 현재 스레드에 저장해둔 스택 포인터를 사용한다.
			// 단, 유저 스택은 페이지 단위로 할당되기 때문에 rsp를 페이지 하단 기준으로 정렬한다.

			if (MAX_STACK <= rsp - 8 && rsp - 8 == addr && addr <= USER_STACK)
			{
				// push 명령어 등으로 인해 rsp보다 낮은 주소에 쓰기를 시도한 경우
				// 스택 프레임 푸시 직전 주소 접근인 경우 (push 명령어 직후에 fault 나는 상황

				if (!vm_stack_growth(addr))
					return false;
			}
			else if (MAX_STACK <= rsp && rsp <= addr && addr <= USER_STACK)
			{
				//  rsp보다 높은 주소에 접근했지만 여전히 스택 영역인 경우
				// 일반적인 스택 사용 (예: 지역 변수 할당 등)으로 인한 접근의 경우

				if (!vm_stack_growth(addr))
					return false;
			}

			page = spt_find_page(spt, addr);
		}

		if (page == NULL || (write && !page->writable))
			return false;

		return vm_do_claim_page(page);
	}
	return false;
}
/* Free the page.
 * DO NOT MODIFY THIS FUNCTION. */
void vm_dealloc_page(struct page *page)
{
	destroy(page);
	free(page);
}

/* Claim the page that allocate on VA. */
// va로 page를 찾아서 vm_do_claim_page를 호출하는 함수
static bool
vm_do_claim_page(struct page *page)
{
	struct frame *frame = vm_get_frame();

	/* Set links */
	frame->page = page;
	page->frame = frame;

	/* TODO: Insert page table entry to map page's VA to frame's PA. */
	// 가상 주소와 물리 주소를 매핑
	struct thread *current = thread_current();
	pml4_set_page(current->pml4, page->va, frame->kva, page->writable);

	return swap_in(page, frame->kva); // uninit_initialize
}
/* Claim the PAGE and set up the mmu. */
bool vm_claim_page(void *va UNUSED)
{
	struct page *page = NULL;
	/* TODO: Fill this function */
	// spt에서 va에 해당하는 page 찾기
	page = spt_find_page(&thread_current()->spt, va);
	if (page == NULL)
		return false;
	return vm_do_claim_page(page);
}

/* Returns a hash value for page p. */
unsigned
page_hash(const struct hash_elem *p_, void *aux UNUSED)
{
	const struct page *p = hash_entry(p_, struct page, hash_elem);
	return hash_bytes(&p->va, sizeof p->va);
}

/* Returns true if page a precedes page b. */
bool page_less(const struct hash_elem *a_,
							 const struct hash_elem *b_, void *aux UNUSED)
{
	const struct page *a = hash_entry(a_, struct page, hash_elem);
	const struct page *b = hash_entry(b_, struct page, hash_elem);

	return a->va < b->va;
}

/* Initialize new supplemental page table */
void supplemental_page_table_init(struct supplemental_page_table *spt UNUSED)
{
	// 인자로 받은 spt의 pages 해시 테이블을 초기화
	hash_init(&spt->spt_pages, page_hash, page_less, NULL);
}

/* Copy supplemental page table from src to dst */
/*
	자식 프로세스 생성시, 부모 프로세스의 SPT를 상속 =>fork 시 spt 복사
	SPT에 있는 모든 페이지를 각 타입에 맞게 할당
*/
bool supplemental_page_table_copy(struct supplemental_page_table *dst UNUSED,
																	struct supplemental_page_table *src UNUSED)
{
	struct hash_iterator i;
	hash_first(&i, &src->spt_pages);
	// 반목문으로 각각의 페이지 확인
	while (hash_next(&i))
	{
		struct page *src_page = hash_entry(hash_cur(&i), struct page, hash_elem);
		enum vm_type type = src_page->operations->type; // 페이지 타입 확인
		void *upage = src_page->va;
		bool writable = src_page->writable;
		if (type == VM_UNINIT) // UNINIT 인 경우
		{
			vm_initializer *init = src_page->uninit.init; // uninit에 맞는 initializer 할당
			void *aux = src_page->uninit.aux;
			(VM_ANON, upage, writable, init, aux);
			continue;
		}

		if (type == VM_FILE)
		{
			struct lazy_load_arg *file_aux = malloc(sizeof(struct lazy_load_arg));
			file_aux->file = src_page->file.file;
			file_aux->ofs = src_page->file.offset;
			file_aux->read_bytes = src_page->file.read_bytes;
			file_aux->zero_bytes = src_page->file.zero_bytes;
			if (!vm_alloc_page_with_initializer(type, upage, writable, NULL, file_aux))
				return false;
			struct page *file_page = spt_find_page(dst, upage);
			file_backed_initializer(file_page, type, NULL);
			file_page->frame = src_page->frame;
			pml4_set_page(thread_current()->pml4, file_page->va, src_page->frame->kva, src_page->writable);
			continue;
		}

		// UNINIT 아닌 경우
		if (!vm_alloc_page(type, upage, writable)) // uninit page 생성 & 초기화
			// init이랑 aux는 Lazy Loading에 필요함
			// 지금 만드는 페이지는 기다리지 않고 바로 내용을 넣어줄 것이므로 필요 없음
			return false;

		// vm_claim_page으로 요청해서 매핑 & 페이지 타입에 맞게 초기화
		if (!vm_claim_page(upage))
			return false;

		// 매핑된 프레임에 내용 로딩
		struct page *dst_page = spt_find_page(dst, upage);
		memcpy(dst_page->frame->kva, src_page->frame->kva, PGSIZE);
	}
	return true;
}

/* Free the resource hold by the supplemental page table */
void supplemental_page_table_kill(struct supplemental_page_table *spt UNUSED)
{
	/* TODO: Destroy all the supplemental_page_table hold by thread and
	 * TODO: writeback all the modified contents to the storage. */
	hash_clear(&spt->spt_pages, hash_page_destroy);
}

void hash_page_destroy(struct hash_elem *e, void *aux)
{
	struct page *page = hash_entry(e, struct page, hash_elem);
	destroy(page);
	free(page);
}