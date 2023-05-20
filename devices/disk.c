#include "devices/disk.h"
#include <ctype.h>
#include <debug.h>
#include <stdbool.h>
#include <stdio.h>
#include "devices/timer.h"
#include "threads/io.h"
#include "threads/interrupt.h"
#include "threads/synch.h"

/* The code in this file is an interface to an ATA (IDE)
   controller.  It attempts to comply to [ATA-3]. */

/* ATA command block port addresses. */
#define reg_data(CHANNEL) ((CHANNEL)->reg_base + 0)     /* Data. */
#define reg_error(CHANNEL) ((CHANNEL)->reg_base + 1)    /* Error. */
#define reg_nsect(CHANNEL) ((CHANNEL)->reg_base + 2)    /* Sector Count. */
#define reg_lbal(CHANNEL) ((CHANNEL)->reg_base + 3)     /* LBA 0:7. */
#define reg_lbam(CHANNEL) ((CHANNEL)->reg_base + 4)     /* LBA 15:8. */
#define reg_lbah(CHANNEL) ((CHANNEL)->reg_base + 5)     /* LBA 23:16. */
#define reg_device(CHANNEL) ((CHANNEL)->reg_base + 6)   /* Device/LBA 27:24. */
#define reg_status(CHANNEL) ((CHANNEL)->reg_base + 7)   /* Status (r/o). */
#define reg_command(CHANNEL) reg_status (CHANNEL)       /* Command (w/o). */

/* ATA control block port addresses.
   (If we supported non-legacy ATA controllers this would not be
   flexible enough, but it's fine for what we do.) */
#define reg_ctl(CHANNEL) ((CHANNEL)->reg_base + 0x206)  /* Control (w/o). */
#define reg_alt_status(CHANNEL) reg_ctl (CHANNEL)       /* Alt Status (r/o). */

/* Alternate Status Register bits. */
#define STA_BSY 0x80            /* Busy. */
#define STA_DRDY 0x40           /* Device Ready. */
#define STA_DRQ 0x08            /* Data Request. */

/* Control Register bits. */
#define CTL_SRST 0x04           /* Software Reset. */

/* Device Register bits. */
#define DEV_MBS 0xa0            /* Must be set. */
#define DEV_LBA 0x40            /* Linear based addressing. */
#define DEV_DEV 0x10            /* Select device: 0=master, 1=slave. */

/* Commands.
   Many more are defined but this is the small subset that we
   use. */
#define CMD_IDENTIFY_DEVICE 0xec        /* IDENTIFY DEVICE. */
#define CMD_READ_SECTOR_RETRY 0x20      /* READ SECTOR with retries. */
#define CMD_WRITE_SECTOR_RETRY 0x30     /* WRITE SECTOR with retries. */

/* An ATA device. */
struct disk {
	char name[8];               /* Name, e.g. "hd0:1". */
	struct channel *channel;    /* Channel disk is on. */
	int dev_no;                 /* Device 0 or 1 for master or slave. */

	bool is_ata;                /* 1=This device is an ATA disk. */
	disk_sector_t capacity;     /* Capacity in sectors (if is_ata). */

	long long read_cnt;         /* Number of sectors read. */
	long long write_cnt;        /* Number of sectors written. */
};

/* An ATA channel (aka controller).
   Each channel can control up to two disks. */
struct channel {
	char name[8];               /* Name, e.g. "hd0". */
	uint16_t reg_base;          /* Base I/O port. */
	uint8_t irq;                /* Interrupt in use. */

	struct lock lock;           /* Must acquire to access the controller. */
	bool expecting_interrupt;   /* True if an interrupt is expected, false if
								   any interrupt would be spurious. */
	struct semaphore completion_wait;   /* Up'd by interrupt handler. */

	struct disk devices[2];     /* The devices on this channel. */
};

/* We support the two "legacy" ATA channels found in a standard PC. */
#define CHANNEL_CNT 2
static struct channel channels[CHANNEL_CNT];

static void reset_channel (struct channel *);
static bool check_device_type (struct disk *);
static void identify_ata_device (struct disk *);

static void select_sector (struct disk *, disk_sector_t);
static void issue_pio_command (struct channel *, uint8_t command);
static void input_sector (struct channel *, void *);
static void output_sector (struct channel *, const void *);

static void wait_until_idle (const struct disk *);
static bool wait_while_busy (const struct disk *);
static void select_device (const struct disk *);
static void select_device_wait (const struct disk *);

static void interrupt_handler (struct intr_frame *);

/* Initialize the disk subsystem and detect disks. */
void
disk_init (void) {
	size_t chan_no;

	for (chan_no = 0; chan_no < CHANNEL_CNT; chan_no++) {
		struct channel *c = &channels[chan_no];
		int dev_no;

		/* Initialize channel. */
		snprintf (c->name, sizeof c->name, "hd%zu", chan_no);
		switch (chan_no) {
			case 0:
				c->reg_base = 0x1f0;
				c->irq = 14 + 0x20;
				break;
			case 1:
				c->reg_base = 0x170;
				c->irq = 15 + 0x20;
				break;
			default:
				NOT_REACHED ();
		}
		lock_init (&c->lock);
		c->expecting_interrupt = false;
		sema_init (&c->completion_wait, 0);

		/* Initialize devices. */
		for (dev_no = 0; dev_no < 2; dev_no++) {
			struct disk *d = &c->devices[dev_no];
			snprintf (d->name, sizeof d->name, "%s:%d", c->name, dev_no);
			d->channel = c;
			d->dev_no = dev_no;

			d->is_ata = false;
			d->capacity = 0;

			d->read_cnt = d->write_cnt = 0;
		}

		/* Register interrupt handler. */
		intr_register_ext (c->irq, interrupt_handler, c->name);

		/* Reset hardware. */
		reset_channel (c);

		/* Distinguish ATA hard disks from other devices. */
		if (check_device_type (&c->devices[0]))
			check_device_type (&c->devices[1]);

		/* Read hard disk identity information. */
		for (dev_no = 0; dev_no < 2; dev_no++)
			if (c->devices[dev_no].is_ata)
				identify_ata_device (&c->devices[dev_no]);
	}

	/* DO NOT MODIFY BELOW LINES. */
	register_disk_inspect_intr ();
}

/* Prints disk statistics. */
void
disk_print_stats (void) {
	int chan_no;

	for (chan_no = 0; chan_no < CHANNEL_CNT; chan_no++) {
		int dev_no;

		for (dev_no = 0; dev_no < 2; dev_no++) {
			struct disk *d = disk_get (chan_no, dev_no);
			if (d != NULL && d->is_ata)
				printf ("%s: %lld reads, %lld writes\n",
						d->name, d->read_cnt, d->write_cnt);
		}
	}
}

/* Returns the disk numbered DEV_NO--either 0 or 1 for master or
   slave, respectively--within the channel numbered CHAN_NO.

   Pintos uses disks this way:
0:0 - boot loader, command line args, and operating system kernel
0:1 - file system
1:0 - scratch
1:1 - swap
*/

/*
	disk_get() 함수는 주어진 채널 번호(chan_no) 및 장치 번호(dev_no)와 관련된 디스크 구조에 대한 포인터를 검색하는 도우미 함수입니다.
	일반적으로 시스템의 특정 디스크 장치에 액세스하고 상호 작용하는 데 사용됩니다.
*/
struct disk *
disk_get (int chan_no, int dev_no) {
	ASSERT (dev_no == 0 || dev_no == 1);

	if (chan_no < (int) CHANNEL_CNT)
	{ // 함수는 chan_no 매개변수가 전체 채널 수(CHANNEL_CNT)보다 작은지 확인합니다. 그렇다면 주어진 채널 및 장치 번호와 관련된 디스크 구조 검색을 진행합니다.
		struct disk *d = &channels[chan_no].devices[dev_no]; // d라는 디스크 구조에 대한 포인터를 선언하고 chan_no 및 dev_no로 표시된 특정 디스크 장치의 주소를 할당합니다. channels 배열에는 다양한 채널이 포함되어 있으며 각 채널에는 장치 배열이 있습니다.
		if (d->is_ata)																			 // d->is_ata가 true인지 확인하여 디스크 장치가 ATA(Advanced Technology Attachment) 장치임을 나타냅니다. 그렇다면 디스크 구조 d가 유효한 디스크 장치를 나타냄을 의미합니다.
			return d;																					 // 포인터 'd'를 반환하여 지정된 채널 및 장치 번호와 관련된 디스크 구조에 대한 액세스를 제공합니다.
	}
	return NULL;
}

/* Returns the size of disk D, measured in DISK_SECTOR_SIZE-byte
   sectors. */
disk_sector_t
disk_size (struct disk *d) {
	ASSERT (d != NULL);

	return d->capacity;
}

/* Reads sector SEC_NO from disk D into BUFFER, which must have
   room for DISK_SECTOR_SIZE bytes.
   Internally synchronizes accesses to disks, so external
   per-disk locking is unneeded. */
/* 섹터 SEC_NO를 디스크 D에서 버퍼로 읽습니다.
	 공간이 있어야 합니다.
	 내부적으로 디스크에 대한 액세스를 동기화하므로 외부의
	 디스크별 잠금이 필요하지 않습니다. */
/*
	disk_read() 함수는 디스크에서 버퍼로 데이터를 읽는 역할을 합니다.
*/
void
disk_read (struct disk *d, disk_sector_t sec_no, void *buffer) {
	struct channel *c;

	ASSERT (d != NULL);
	ASSERT (buffer != NULL);

	c = d->channel;
	lock_acquire(&c->lock); // lock_acquire(&c->lock)을 호출하여 디스크 채널과 관련된 잠금을 획득합니다. 이렇게 하면 읽기 작업 중에 디스크에 대한 독점 액세스가 보장됩니다.
	select_sector(d, sec_no); // select_sector() 함수가 호출되어 제공된 섹터 번호(sec_no)를 기반으로 디스크(d)에서 읽기에 적합한 섹터를 설정합니다.
	issue_pio_command(c, CMD_READ_SECTOR_RETRY); // issue_pio_command() 함수가 호출되어 선택된 섹터의 읽기를 시작합니다. 채널(c)과 명령(CMD_READ_SECTOR_RETRY)을 매개변수로 전달합니다.
	sema_down(&c->completion_wait);							 //  sema_down(&c->completion_wait)를 호출하여 읽기 작업이 완료되기를 기다립니다. 이 세마포 다운 작업은 읽기 작업이 완료될 때까지 현재 스레드를 차단합니다.
	if (!wait_while_busy(d))										 // 읽기 작업이 완료된 후 함수는 디스크 포인터(d)를 매개변수로 wait_while_busy()를 호출하여 디스크가 여전히 사용 중인지 확인합니다.
		PANIC("%s: disk read failed, sector=%" PRDSNu, d->name, sec_no); // 디스크가 여전히 사용 중이면(읽기 실패를 나타냄) 함수가 패닉 상태가 되고 PANIC()을 사용하여 오류 메시지를 표시합니다.
	input_sector(c, buffer);																					 // 디스크가 사용 중이 아니고 읽기 작업이 성공하면 input_sector() 함수가 호출되어 디스크 채널(c)에서 제공된 버퍼(buffer)로 데이터를 복사합니다.
	d->read_cnt++;																										 // 수행된 읽기 작업의 수를 추적하기 위해 디스크의 읽기 수(d->read_cnt)가 증가합니다.
	lock_release(&c->lock);																						 // lock_release(&c->lock)를 호출하여 디스크 채널과 관련된 잠금을 해제하여 다른 스레드가 디스크에 액세스할 수 있도록 합니다.
}

/* Write sector SEC_NO to disk D from BUFFER, which must contain
   DISK_SECTOR_SIZE bytes.  Returns after the disk has
   acknowledged receiving the data.
   Internally synchronizes accesses to disks, so external
   per-disk locking is unneeded. */
/* 섹터 SEC_NO를 버퍼에서 디스크 D에 쓰기, 여기에는 다음이 포함되어야 합니다.
	 DISK_SECTOR_SIZE 바이트가 포함되어야 합니다.  디스크가 데이터 수신을
	 데이터를 수신했음을 확인한 후 반환합니다.
	 내부적으로 디스크에 대한 액세스를 동기화하므로 외부의
	 디스크별 잠금이 필요하지 않습니다. */

/*
	disk_write() 함수는 버퍼에서 디스크의 지정된 섹터로 데이터를 쓰는 일을 담당합니다.

	요약하면 disk_write()는 디스크를 구성하고 쓰기 명령을 내리고 완료를 기다리고 데이터 섹터를 출력하여 디스크 쓰기 작업을 수행합니다. 오류 사례를 처리하고 작업 중에 디스크 채널에 대한 독점 액세스를 보장합니다.
*/
void
disk_write (struct disk *d, disk_sector_t sec_no, const void *buffer) {
	struct channel *c;

	ASSERT (d != NULL);
	ASSERT (buffer != NULL);

	c = d->channel; // 디스크(d)와 연결된 채널을 검색하고 이를 로컬 변수 c에 할당합니다.
	lock_acquire(&c->lock); // 디스크 쓰기 작업을 수행하는 동안 채널에 대한 독점 액세스를 보장하기 위해 채널 잠금('c->lock')을 획득합니다.
	select_sector(d, sec_no); //  select_sector()를 호출하여 디스크를 구성하고 지정된 섹터(sec_no)에 헤드를 배치합니다.
	issue_pio_command(c, CMD_WRITE_SECTOR_RETRY); // 채널(c)에 명령(CMD_WRITE_SECTOR_RETRY)을 발행하여 쓰기 작업을 시작합니다.
	if (!wait_while_busy(d))											// 'wait_while_busy()' 함수가 호출되어 디스크가 유휴 상태가 될 때까지 기다립니다. 디스크가 진행 중인 작업을 완료할 때까지 차단됩니다.
		PANIC("%s: disk write failed, sector=%" PRDSNu, d->name, sec_no); // 디스크 쓰기 작업이 실패하면(디스크가 응답하지 않거나 오류가 발생했음을 의미) 함수는 'PANIC()'을 호출하여 시스템을 중지하고 오류 메시지를 표시합니다. 오류 메시지에는 쓰기에 실패한 디스크 이름과 섹터 번호가 포함됩니다.
	output_sector(c, buffer);																						// 디스크 쓰기 작업이 성공하면 함수는 채널(c)에서 output_sector()를 호출하고 데이터가 포함된 버퍼를 전달하여 데이터 섹터를 출력합니다.
	sema_down(&c->completion_wait);																			// 'sema_down()' 함수가 호출되어 쓰기 작업이 완료될 때까지 기다립니다. 작업이 완료되면 인터럽트 처리기에 의해 깨어날 때까지 현재 스레드를 차단합니다.
	d->write_cnt++;																											// 쓰기 작업이 완료된 후 함수는 디스크의 쓰기 횟수를 증가시킵니다(d->write_cnt).
	lock_release(&c->lock);																							// 마지막으로 함수는 채널의 잠금을 해제(c->lock)하여 다른 스레드가 디스크에 액세스할 수 있도록 합니다.
}

/* Disk detection and identification. */

static void print_ata_string (char *string, size_t size);

/* Resets an ATA channel and waits for any devices present on it
   to finish the reset. */
static void
reset_channel (struct channel *c) {
	bool present[2];
	int dev_no;

	/* The ATA reset sequence depends on which devices are present,
	   so we start by detecting device presence. */
	for (dev_no = 0; dev_no < 2; dev_no++) {
		struct disk *d = &c->devices[dev_no];

		select_device (d);

		outb (reg_nsect (c), 0x55);
		outb (reg_lbal (c), 0xaa);

		outb (reg_nsect (c), 0xaa);
		outb (reg_lbal (c), 0x55);

		outb (reg_nsect (c), 0x55);
		outb (reg_lbal (c), 0xaa);

		present[dev_no] = (inb (reg_nsect (c)) == 0x55
				&& inb (reg_lbal (c)) == 0xaa);
	}

	/* Issue soft reset sequence, which selects device 0 as a side effect.
	   Also enable interrupts. */
	outb (reg_ctl (c), 0);
	timer_usleep (10);
	outb (reg_ctl (c), CTL_SRST);
	timer_usleep (10);
	outb (reg_ctl (c), 0);

	timer_msleep (150);

	/* Wait for device 0 to clear BSY. */
	if (present[0]) {
		select_device (&c->devices[0]);
		wait_while_busy (&c->devices[0]);
	}

	/* Wait for device 1 to clear BSY. */
	if (present[1]) {
		int i;

		select_device (&c->devices[1]);
		for (i = 0; i < 3000; i++) {
			if (inb (reg_nsect (c)) == 1 && inb (reg_lbal (c)) == 1)
				break;
			timer_msleep (10);
		}
		wait_while_busy (&c->devices[1]);
	}
}

/* Checks whether device D is an ATA disk and sets D's is_ata
   member appropriately.  If D is device 0 (master), returns true
   if it's possible that a slave (device 1) exists on this
   channel.  If D is device 1 (slave), the return value is not
   meaningful. */
static bool
check_device_type (struct disk *d) {
	struct channel *c = d->channel;
	uint8_t error, lbam, lbah, status;

	select_device (d);

	error = inb (reg_error (c));
	lbam = inb (reg_lbam (c));
	lbah = inb (reg_lbah (c));
	status = inb (reg_status (c));

	if ((error != 1 && (error != 0x81 || d->dev_no == 1))
			|| (status & STA_DRDY) == 0
			|| (status & STA_BSY) != 0) {
		d->is_ata = false;
		return error != 0x81;
	} else {
		d->is_ata = (lbam == 0 && lbah == 0) || (lbam == 0x3c && lbah == 0xc3);
		return true;
	}
}

/* Sends an IDENTIFY DEVICE command to disk D and reads the
   response.  Initializes D's capacity member based on the result
   and prints a message describing the disk to the console. */
static void
identify_ata_device (struct disk *d) {
	struct channel *c = d->channel;
	uint16_t id[DISK_SECTOR_SIZE / 2];

	ASSERT (d->is_ata);

	/* Send the IDENTIFY DEVICE command, wait for an interrupt
	   indicating the device's response is ready, and read the data
	   into our buffer. */
	select_device_wait (d);
	issue_pio_command (c, CMD_IDENTIFY_DEVICE);
	sema_down (&c->completion_wait);
	if (!wait_while_busy (d)) {
		d->is_ata = false;
		return;
	}
	input_sector (c, id);

	/* Calculate capacity. */
	d->capacity = id[60] | ((uint32_t) id[61] << 16);

	/* Print identification message. */
	printf ("%s: detected %'"PRDSNu" sector (", d->name, d->capacity);
	if (d->capacity > 1024 / DISK_SECTOR_SIZE * 1024 * 1024)
		printf ("%"PRDSNu" GB",
				d->capacity / (1024 / DISK_SECTOR_SIZE * 1024 * 1024));
	else if (d->capacity > 1024 / DISK_SECTOR_SIZE * 1024)
		printf ("%"PRDSNu" MB", d->capacity / (1024 / DISK_SECTOR_SIZE * 1024));
	else if (d->capacity > 1024 / DISK_SECTOR_SIZE)
		printf ("%"PRDSNu" kB", d->capacity / (1024 / DISK_SECTOR_SIZE));
	else
		printf ("%"PRDSNu" byte", d->capacity * DISK_SECTOR_SIZE);
	printf (") disk, model \"");
	print_ata_string ((char *) &id[27], 40);
	printf ("\", serial \"");
	print_ata_string ((char *) &id[10], 20);
	printf ("\"\n");
}

/* Prints STRING, which consists of SIZE bytes in a funky format:
   each pair of bytes is in reverse order.  Does not print
   trailing whitespace and/or nulls. */
static void
print_ata_string (char *string, size_t size) {
	size_t i;

	/* Find the last non-white, non-null character. */
	for (; size > 0; size--) {
		int c = string[(size - 1) ^ 1];
		if (c != '\0' && !isspace (c))
			break;
	}

	/* Print. */
	for (i = 0; i < size; i++)
		printf ("%c", string[i ^ 1]);
}

/* Selects device D, waiting for it to become ready, and then
   writes SEC_NO to the disk's sector selection registers.  (We
   use LBA mode.) */
static void
select_sector (struct disk *d, disk_sector_t sec_no) {
	struct channel *c = d->channel;

	ASSERT (sec_no < d->capacity);
	ASSERT (sec_no < (1UL << 28));

	select_device_wait (d);
	outb (reg_nsect (c), 1);
	outb (reg_lbal (c), sec_no);
	outb (reg_lbam (c), sec_no >> 8);
	outb (reg_lbah (c), (sec_no >> 16));
	outb (reg_device (c),
			DEV_MBS | DEV_LBA | (d->dev_no == 1 ? DEV_DEV : 0) | (sec_no >> 24));
}

/* Writes COMMAND to channel C and prepares for receiving a
   completion interrupt. */
static void
issue_pio_command (struct channel *c, uint8_t command) {
	/* Interrupts must be enabled or our semaphore will never be
	   up'd by the completion handler. */
	ASSERT (intr_get_level () == INTR_ON);

	c->expecting_interrupt = true;
	outb (reg_command (c), command);
}

/* Reads a sector from channel C's data register in PIO mode into
   SECTOR, which must have room for DISK_SECTOR_SIZE bytes. */
static void
input_sector (struct channel *c, void *sector) {
	insw (reg_data (c), sector, DISK_SECTOR_SIZE / 2);
}

/* Writes SECTOR to channel C's data register in PIO mode.
   SECTOR must contain DISK_SECTOR_SIZE bytes. */
static void
output_sector (struct channel *c, const void *sector) {
	outsw (reg_data (c), sector, DISK_SECTOR_SIZE / 2);
}

/* Low-level ATA primitives. */

/* Wait up to 10 seconds for the controller to become idle, that
   is, for the BSY and DRQ bits to clear in the status register.

   As a side effect, reading the status register clears any
   pending interrupt. */
static void
wait_until_idle (const struct disk *d) {
	int i;

	for (i = 0; i < 1000; i++) {
		if ((inb (reg_status (d->channel)) & (STA_BSY | STA_DRQ)) == 0)
			return;
		timer_usleep (10);
	}

	printf ("%s: idle timeout\n", d->name);
}

/* Wait up to 30 seconds for disk D to clear BSY,
   and then return the status of the DRQ bit.
   The ATA standards say that a disk may take as long as that to
   complete its reset. */
static bool
wait_while_busy (const struct disk *d) {
	struct channel *c = d->channel;
	int i;

	for (i = 0; i < 3000; i++) {
		if (i == 700)
			printf ("%s: busy, waiting...", d->name);
		if (!(inb (reg_alt_status (c)) & STA_BSY)) {
			if (i >= 700)
				printf ("ok\n");
			return (inb (reg_alt_status (c)) & STA_DRQ) != 0;
		}
		timer_msleep (10);
	}

	printf ("failed\n");
	return false;
}

/* Program D's channel so that D is now the selected disk. */
static void
select_device (const struct disk *d) {
	struct channel *c = d->channel;
	uint8_t dev = DEV_MBS;
	if (d->dev_no == 1)
		dev |= DEV_DEV;
	outb (reg_device (c), dev);
	inb (reg_alt_status (c));
	timer_nsleep (400);
}

/* Select disk D in its channel, as select_device(), but wait for
   the channel to become idle before and after. */
static void
select_device_wait (const struct disk *d) {
	wait_until_idle (d);
	select_device (d);
	wait_until_idle (d);
}

/* ATA interrupt handler. */
static void
interrupt_handler (struct intr_frame *f) {
	struct channel *c;

	for (c = channels; c < channels + CHANNEL_CNT; c++)
		if (f->vec_no == c->irq) {
			if (c->expecting_interrupt) {
				inb (reg_status (c));               /* Acknowledge interrupt. */
				sema_up (&c->completion_wait);      /* Wake up waiter. */
			} else
				printf ("%s: unexpected interrupt\n", c->name);
			return;
		}

	NOT_REACHED ();
}

static void
inspect_read_cnt (struct intr_frame *f) {
	struct disk * d = disk_get (f->R.rdx, f->R.rcx);
	f->R.rax = d->read_cnt;
}

static void
inspect_write_cnt (struct intr_frame *f) {
	struct disk * d = disk_get (f->R.rdx, f->R.rcx);
	f->R.rax = d->write_cnt;
}

/* Tool for testing disk r/w cnt. Calling this function via int 0x43 and int 0x44.
 * Input:
 *   @RDX - chan_no of disk to inspect
 *   @RCX - dev_no of disk to inspect
 * Output:
 *   @RAX - Read/Write count of disk. */
void
register_disk_inspect_intr (void) {
	intr_register_int (0x43, 3, INTR_OFF, inspect_read_cnt, "Inspect Disk Read Count");
	intr_register_int (0x44, 3, INTR_OFF, inspect_write_cnt, "Inspect Disk Write Count");
}
