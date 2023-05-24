#include "userprog/syscall.h"

#include <stdio.h>
#include <syscall-nr.h>

#include "intrinsic.h"
#include "threads/flags.h"
#include "threads/interrupt.h"
#include "threads/loader.h"
#include "threads/thread.h"
#include "userprog/gdt.h"

/* helper function for syscall_handler */
static struct page *validate_usr_addr(void *addr);
static void get_argument(uintptr_t *rsp, uintptr_t *arg, int count);

/* System calls */
static void sys_halt(void);
static void sys_exit(int status);
static tid_t fork(const char *thread_name, struct intr_frame *f);
static tid_t sys_exec(const char *cmd_line);
static int sys_wait(tid_t pid);
static bool sys_create(const char *file, unsigned initial_size);
static bool sys_remove(const char *file);
static int sys_open(const char *file);
static int sys_filesize(int fd);
static int sys_read(int fd, void *buffer, unsigned size);
static int sys_write(int fd, const void *buffer, unsigned size);
static void sys_seek(int fd, unsigned position);
static unsigned sys_tell(int fd);
static void sys_close(int fd);
static int sys_dup2(int oldfd, int newfd);
static void *sys_mmap(void *addr, size_t length, int writable, int fd, off_t offset);
static void sys_munmap(void *addr);

void syscall_entry(void);
void syscall_handler(struct intr_frame *);

#define SET_RAX(f, val) (f->R.rax = (uint64_t)val)

/* System call.
 *
 * Previously system call services was handled by the interrupt handler
 * (e.g. int 0x80 in linux). However, in x86-64, the manufacturer supplies
 * efficient path for requesting the system call, the `syscall` instruction.
 *
 * The syscall instruction works by reading the values from the the Model
 * Specific Register (MSR). For the details, see the manual. */

#define MSR_STAR 0xc0000081         /* Segment selector msr */
#define MSR_LSTAR 0xc0000082        /* Long mode SYSCALL target */
#define MSR_SYSCALL_MASK 0xc0000084 /* Mask for the eflags */

extern struct lock filesys_lock;
extern uint64_t stdin_file;
extern uint64_t stdout_file;

void syscall_init(void)
{
    write_msr(MSR_STAR, ((uint64_t)SEL_UCSEG - 0x10) << 48 |
                            ((uint64_t)SEL_KCSEG) << 32);
    write_msr(MSR_LSTAR, (uint64_t)syscall_entry);

    /* The interrupt service rountine should not serve any interrupts
     * until the syscall_entry swaps the userland stack to the kernel
     * mode stack. Therefore, we masked the FLAG_FL. */
    write_msr(MSR_SYSCALL_MASK,
              FLAG_IF | FLAG_TF | FLAG_DF | FLAG_IOPL | FLAG_AC | FLAG_NT);

    lock_init(&filesys_lock);
}

/*
    validate_usr_addr() 함수는 Pintos 프로젝트에서 사용자 주소를 확인하고 주소에 해당하는 struct page를 검색하는 데 사용됩니다.

    요약하면 validate_usr_addr() 함수는 사용자 주소가 커널 주소가 아닌지 확인하는 역할을 합니다. 주소가 커널 주소이면 프로그램을 종료합니다.
    그렇지 않으면 스레드의 추가 페이지 테이블에서 주소를 조회하고 해당 struct page를 반환합니다.
*/
struct page *validate_usr_addr(void *addr)
{
    if (is_kernel_vaddr(addr)) // is_kernel_vaddr() 함수를 호출하여 주어진 주소 addr이 커널 가상 주소인지 확인합니다. 커널 가상 주소는 커널 공간에 속하는 주소로 사용자 프로그램에서 접근할 수 없습니다.
    {
        sys_exit(-1); // sys_exit(-1): 종료 상태가 -1인 sys_exit() 함수를 호출하여 현재 사용자 프로그램을 종료합니다. 이것은 사용자 공간에서 커널 주소에 액세스하는 데 오류가 있음을 나타냅니다.
        NOT_REACHED(); // NOT_REACHED(): 코드에서 이 지점에 절대 도달해서는 안된다는 것을 나타내는 매크로입니다. 이전 단계에서 프로그램이 종료되었어야 하기 때문입니다.
    }
    return spt_find_page(&thread_current()->spt, addr); // spt_find_page() 함수를 호출하여 해당하는 struct page를 찾는다. 현재 스레드. spt_find_page() 함수는 주소를 기반으로 페이지 항목을 검색하고 발견되면 struct page에 대한 포인터를 반환합니다.
}

/*
    validate_buffer() 함수는 Pintos 프로젝트에서 사용자 공간의 버퍼를 검증하여 액세스 가능성과 권한을 보장하는 데 사용됩니다.

    validate_buffer() 함수는 액세스 가능성, 경계 및 권한을 확인하여 사용자 공간의 버퍼를 검증합니다.
    버퍼 범위 내의 각 페이지를 확인하여 페이지가 유효하고 요청된 작업에 필요한 권한이 있는지 확인합니다.
    유효성 검사에 실패하면 프로그램이 종료됩니다.
*/
void validate_buffer(void *buffer, size_t size, bool to_write)
{
    if (buffer == NULL) // 주어진 버퍼가 NULL인지 확인합니다. 버퍼가 NULL이면 유효하지 않은 버퍼임을 나타내며 종료 상태가 -1인 sys_exit() 함수를 사용하여 프로그램이 종료됩니다.
        sys_exit(-1);

    void *start_addr = pg_round_down(buffer); // 버퍼 주소를 가장 가까운 페이지 경계까지 내림하여 start_addr에 할당합니다. 이렇게 하면 페이지의 시작 주소로 작업할 수 있습니다.
    void *end_addr = pg_round_down(buffer + size); // 버퍼 주소에 크기를 더하고 가장 가까운 페이지 경계까지 내림하여 버퍼의 끝 주소를 계산합니다. 이것은 버퍼를 포함하는 마지막 페이지의 끝 주소를 제공합니다.

    ASSERT(start_addr <= end_addr); // 시작 주소가 끝 주소보다 작거나 같다고 주장합니다. 이 검사는 버퍼 범위가 유효하고 적절하게 정의되었는지 확인합니다.
    for (void *addr = end_addr; addr >= start_addr; addr -= PGSIZE) // addr -= PGSIZE는 버퍼 범위를 역순으로 반복하며, 끝 주소에서 시작하여 PGSIZE(페이지 크기)의 단계 크기로 시작 주소를 향해 이동합니다.
    {
        struct page *pg = validate_usr_addr(addr); // validate_usr_addr() 함수를 호출하여 버퍼 범위 내의 각 페이지를 검증합니다. validate_usr_addr() 함수는 주소가 유효한 사용자 주소인지 확인하고 해당 struct page에 대한 포인터를 반환합니다.
        if (pg == NULL)                            // validate_usr_addr()에 의해 반환된 페이지 항목이 NULL인지 확인합니다. NULL이면 페이지가 유효하지 않음을 의미하며 sys_exit()를 사용하여 프로그램이 종료됩니다.
        {
            sys_exit(-1);
        }
        if (pg->writable == false && to_write == true) // 페이지의 writable 플래그가 false인지 확인합니다(페이지가 읽기 전용임을 나타냄) 그리고 to_write 플래그는 true입니다(쓰기 작업이 요청되었음을 나타냄). 두 조건이 모두 참이면 읽기 전용 페이지에 쓰기를 시도하고 sys_exit()를 사용하여 프로그램이 종료됨을 의미합니다.
        {
            // printf("%s: pg->writable: %p\n", thread_current()->name, pg->writable);
            sys_exit(-1);
        }
    }
}

void get_argument(uintptr_t *rsp, uintptr_t *arg, int count)
{
    printf("%x\n", *rsp);
    for (int tmp = 0; tmp < count; ++tmp)
    {
        validate_usr_addr(*rsp);
        arg[tmp] = *(uintptr_t *)*rsp;
        *rsp += sizeof(uintptr_t);
    }
}

void check_bad_ptr(void *addr)
{
    if (addr == NULL)
        sys_exit(-1);

    if (validate_usr_addr(addr) == NULL)
        sys_exit(-1);

    if (pml4_get_page(thread_current()->pml4, addr) == NULL)
        sys_exit(-1);
}

/* The main system call interface */
void syscall_handler(struct intr_frame *f)
{
    // TODO: Your implementation goes here.
    uint64_t args[5] = {f->R.rdi, f->R.rsi, f->R.rdx, f->R.r10, f->R.r8};
    thread_current()->user_rsp = f->rsp;

    switch ((int)(f->R.rax))
    {
    case SYS_HALT:
        sys_halt();
        break;

    case SYS_EXIT:
        sys_exit((int)args[0]);
        break;

    case SYS_FORK:
        SET_RAX(f, sys_fork((char *)args[0], f));
        break;

    case SYS_EXEC:
        SET_RAX(f, sys_exec((char *)args[0]));
        break;

    case SYS_WAIT:
        SET_RAX(f, sys_wait((tid_t)args[0]));
        break;

    case SYS_CREATE:
        SET_RAX(f, sys_create((char *)args[0], (unsigned)args[1]));
        break;

    case SYS_REMOVE:
        SET_RAX(f, sys_remove((char *)args[0]));
        break;

    case SYS_OPEN:
        SET_RAX(f, sys_open((char *)args[0]));
        break;

    case SYS_FILESIZE:
        SET_RAX(f, sys_filesize((int)args[0]));
        break;

    case SYS_READ:
        SET_RAX(f, sys_read((int)args[0], (void *)args[1], (unsigned)args[2]));
        break;

    case SYS_WRITE:
        SET_RAX(f, sys_write((int)args[0], (void *)args[1], (unsigned)args[2]));
        break;

    case SYS_SEEK:
        sys_seek((int)args[0], (unsigned)args[1]);
        break;

    case SYS_TELL:
        SET_RAX(f, sys_tell((int)args[0]));
        break;

    case SYS_CLOSE:
        sys_close((int)args[0]);
        break;

    case SYS_DUP2:
        SET_RAX(f, sys_dup2((int)args[0], (int)args[1]));
        break;

    case SYS_MMAP:
        SET_RAX(f, sys_mmap((void *)args[0], (size_t)args[1], (int)args[2], (int)args[3], (off_t)args[4]));
        break;

    case SYS_MUNMAP:
        sys_munmap((void *)args[0]);
        break;

    default:
        thread_exit();
    }
}

/* System calls */
void sys_halt(void)
{
    power_off();
    NOT_REACHED();
}

void sys_exit(int status)
{
    struct thread *curr = thread_current();
    thread_current()->exit_status = status;
    thread_exit();
}

tid_t sys_fork(const char *thread_name, struct intr_frame *f)
{
    check_bad_ptr(thread_name);

    lock_acquire(&filesys_lock);
    tid_t fork_result = process_fork(thread_name, f);
    lock_release(&filesys_lock);

    return fork_result;
}

int sys_exec(const char *cmd_line)
{
    check_bad_ptr(cmd_line);

    void *cmd_copy;
    cmd_copy = palloc_get_page(0);
    if (cmd_copy == NULL)
        return -1;
    // cmd_copy += 0x8000000000;
    strlcpy(cmd_copy, cmd_line, PGSIZE);

    // create child process
    process_exec(cmd_copy);
    sys_exit(-1);
    return -1;
}

int sys_wait(tid_t pid)
{
    int status = process_wait(pid);
    return status;
}

bool sys_create(const char *file, unsigned initial_size)
{
    check_bad_ptr(file);

    lock_acquire(&filesys_lock);
    bool create_result = filesys_create(file, initial_size);
    lock_release(&filesys_lock);
    return create_result;
}

bool sys_remove(const char *file)
{
    // check validity
    check_bad_ptr(file);

    lock_acquire(&filesys_lock);
    bool remove_result = filesys_remove(file);
    lock_release(&filesys_lock);
    return remove_result;
}

int sys_open(const char *file)
{
    check_bad_ptr(file);

    if (*file == '\0')
        return -1;

    lock_acquire(&filesys_lock);
    void *f = filesys_open(file);
    lock_release(&filesys_lock);

    if (f == NULL)
        return -1;
    f += 0x8000000000;

    return process_add_file(f);
}

int sys_filesize(int fd)
{
    void *f = process_get_file(fd);

    if (f == NULL)
        return -1;
    f += 0x8000000000;

    lock_acquire(&filesys_lock);
    int length_result = (int)file_length(f);
    lock_release(&filesys_lock);
    return length_result;
}

int sys_read(int fd, void *buffer, unsigned size)
{

    struct thread *curr = thread_current();
    validate_buffer(buffer, size, true);
    lock_acquire(&filesys_lock);

    int read;

    void *f = process_get_file(fd);
    if (f == NULL)
    {
        lock_release(&filesys_lock);
        sys_exit(-1);
    }
    f += 0x8000000000;

    if (f == (void *)&stdin_file)
    {
        read = input_getc();
        lock_release(&filesys_lock);
        return read;
    }
    if (f == (void *)&stdout_file)
    {
        lock_release(&filesys_lock);
        sys_exit(-1);
    }
    read = (int)file_read(f, buffer, (off_t)size);

    lock_release(&filesys_lock);
    return read;
}

int sys_write(int fd, const void *buffer, unsigned size)
{
    validate_buffer(buffer, size, false);
    lock_acquire(&filesys_lock);

    void *f = process_get_file(fd);
    if (f == NULL)
    {
        lock_release(&filesys_lock);
        sys_exit(-1);
    }

    f += 0x8000000000;

    if (f == (void *)&stdout_file)
    {
        putbuf(buffer, size);
        lock_release(&filesys_lock);
        return size;
    }

    if (f == (void *)&stdin_file)
    {
        lock_release(&filesys_lock);
        sys_exit(-1);
    }

    int written = (int)file_write(f, buffer, (off_t)size);
    lock_release(&filesys_lock);
    return written;
}

void sys_seek(int fd, unsigned position)
{
    void *f = process_get_file(fd);

    if (f == NULL)
        return;
    f += 0x8000000000;

    lock_acquire(&filesys_lock);
    file_seek(f, (off_t)position);
    lock_release(&filesys_lock);
}

unsigned sys_tell(int fd)
{
    void *f = process_get_file(fd);

    if (f == NULL)
        return -1;

    f += 0x8000000000;
    lock_acquire(&filesys_lock);
    unsigned tell_result = (unsigned)file_tell(f);
    lock_release(&filesys_lock);
    return tell_result;
}

void sys_close(int fd)
{
    if (process_close_file(fd) == false)
        sys_exit(-1);
}

int sys_dup2(int oldfd, int newfd)
{
    struct thread *current = thread_current();
    void *old_f = process_get_file(oldfd);

    if (old_f == NULL)
        return -1;

    if (newfd < 0)
        return -1;

    if (oldfd == newfd)
        return newfd;

    // extend fd table if required (newfd >= current->next_fd)
    if (newfd >= current->next_fd)
    {
        void *old_fd_table = current->fd_table;
        current->fd_table = (struct file **)realloc(current->fd_table, sizeof(struct file *) * (newfd + 1));
        if (current->fd_table == NULL)
        {
            current->fd_table = old_fd_table;
            sys_exit(-1);
        }

        for (int i = current->next_fd; i <= newfd; i++)
            current->fd_table[i] = NULL;

        current->next_fd = newfd + 1;
    }

    // close newfd contents
    if (process_get_file(newfd) != NULL)
        process_close_file(newfd);

    current->fd_table[newfd] = current->fd_table[oldfd];

    return newfd;
}

/*
    mmap :
    파일 디스크립터 fd로 오픈한 파일을 offset byte 위치에서부터 시작해 length 바이트 크기만큼 읽어들여 addr에 위치한 프로세스 가상 주소 공간에 매핑한다.
    전체 파일은 페이지 단위로 나뉘어 연속적인 가상 주소 페이지에 매핑된다. 즉, mmap()은 메모리를 페이지 단위로 할당받는 시스템 콜이다.

    sys_mmap() 함수는 제공된 매개변수에 대한 다양한 검사를 수행하고 주소 범위, 파일 존재, 오프셋 및 길이를 확인하여 mmap() 시스템 호출을 처리합니다.
    모든 검사가 통과되면 do_mmap() 함수를 호출하여 실제 메모리 매핑을 수행하고 성공하면 매핑된 주소를 반환합니다.

    파일에 가상 페이지 매핑을 해줘도 적합한지를 체크해주는 함수
*/
static void *sys_mmap(void *addr, size_t length, int writable, int fd, off_t offset)
{
    if (addr == NULL)
        return NULL;

    // 그것은 오프셋이 페이지 크기 PGSIZE에 정렬되어 있는지 확인하고 그렇지 않은 경우 NULL을 반환하여 적절한 정렬을 보장합니다.
    if (offset % PGSIZE != 0)
        return NULL;

    // addr이 커널 주소 범위 내에 있는지 확인하고 true인 경우 NULL을 반환하여 커널 공간으로의 매핑을 방지합니다.
    if (is_kernel_vaddr(addr))
        return NULL;

    // addr + length가 커널 주소 범위 내에 있는지 확인하고 true인 경우 NULL을 반환하여 커널 공간으로의 매핑을 방지합니다.
    if (is_kernel_vaddr((size_t)addr + length))
        return NULL;

    if ((long)length <= 0)
        return NULL;

    // pg_round_down()을 사용하여 addr이 이미 페이지 정렬되었는지 확인하고 그렇지 않은 경우 NULL을 반환합니다.
    if (addr != pg_round_down(addr))
        return NULL;

    void *start_addr = pg_round_down(addr);
    void *end_addr = pg_round_down(addr + length);
    ASSERT(start_addr <= end_addr);

    /*
        end_addr에서 start_addr까지 반복하여 validate_usr_addr()을 ​​사용하여 기존 struct page에 대한 각 페이지 정렬 주소를 확인합니다.
        struct page가 발견되면 해당 영역이 이미 매핑된 것이므로 NULL을 반환합니다.
    */
    for (void *addr = end_addr; addr >= start_addr; addr -= PGSIZE)
    {
        struct page *pg = validate_usr_addr(addr);
        if (pg != NULL)
        {
            return NULL;
        }
    }

    void *file = process_get_file(fd); // process_get_file()을 사용하여 주어진 파일 설명자 fd에 해당하는 파일을 검색합니다. 파일이 없으면 NULL을 반환합니다.
    if (file == NULL)
        return NULL;

    file += 0x8000000000; // 변수 'file'은 오프셋('0x8000000000')을 추가하도록 조정되어 파일 포인터와 커널 가상 주소를 구분합니다.

    if ((file == &stdin_file) || (file == &stdout_file)) // 파일이 표준 입력 또는 출력 파일인지 확인하고 매핑을 방지하기 위해 true인 경우 NULL을 반환합니다.
        return NULL;

    off_t file_len = file_length(file); // file_length()를 사용하여 파일의 길이를 검색합니다. 파일 길이가 0이면 NULL을 반환합니다.
    if (file_len == 0)
        return NULL;

    if (file_len <= offset) // 파일 길이가 주어진 오프셋보다 작거나 같은지 확인하고 참이면 NULL을 반환하여 잘못된 오프셋을 나타냅니다.
        return NULL;

    struct thread *curr_thraed = thread_current(); // thread_current()를 사용하여 현재 스레드를 검색하고 curr_thread 변수에 할당합니다.
    file_len = file_len < length ? file_len : length; // file_len과 length 중에서 더 작은 값을 선택하여 매핑의 실제 길이를 결정합니다.
    lock_acquire(&filesys_lock);                      // 파일 시스템에 대한 독점 액세스를 보장하기 위해 filesys_lock을 획득하고
    void *success = do_mmap(addr, (size_t)file_len, writable, file, offset); // do_mmap() 함수를 호출하여 실제 매핑을 수행합니다. 결과 주소는 success 변수에 저장됩니다.
    lock_release(&filesys_lock); // filesys_lock을 해제합니다.

    return success; // 성공하면 매핑된 주소를 포함하고 그렇지 않으면 'NULL'을 포함하는 'success' 변수를 반환합니다.
}

/*
    munmap() 함수는 우리가 지우고 싶은 주소 addr 로부터 연속적인 유저 가상 페이지의 변경 사항을 디스크 파일에 업데이트한 뒤, 매핑 정보를 지운다.
    여기서 중요한 점은 페이지를 지우는 게 아니라 present bit을 0으로 만들어준다는 점이다.
    따라서 munmap() 함수는 정확히는 지정된 주소 범위 addr에 대한 매핑을 해제하는 함수라고 봐야겠다
*/
static void sys_munmap(void *addr)
{
    if (addr == NULL)
        return;

    if (is_kernel_vaddr(addr))
        return;

    struct thread *curr_thread = thread_current();
    struct page *page = spt_find_page(&(curr_thread->spt), addr);
    if (page == NULL)
        return;

    if (page->operations->type != VM_FILE)
        return;

    if (addr != page->file.start)
        return;

    do_munmap(addr);
    return;
}