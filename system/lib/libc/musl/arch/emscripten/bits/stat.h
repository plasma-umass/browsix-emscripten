/* copied from kernel definition, but with padding replaced
 * by the corresponding correctly-sized userspace types. */

struct stat
{
	dev_t st_dev;
  dev_t __st_dev_pad;
	ino_t st_ino;
	ino_t __st_ino_pad;
	nlink_t st_nlink;
	nlink_t __st_nlink_pad;

	mode_t st_mode;
	uid_t st_uid;
	gid_t st_gid;
	unsigned int    __pad0;
	dev_t st_rdev;
	dev_t __st_rdev_pad;
	off_t st_size;
	off_t __st_size_pad;
	blksize_t st_blksize;
	blksize_t __st_blksize_pad;
	blkcnt_t st_blocks;
	blkcnt_t __st_blocks_pad;

	struct timespec st_atim;
	struct timespec st_mtim;
	struct timespec st_ctim;
	long long __unused[3];
};
