.globl AKepoll_create
.globl AKepoll_ctl
.globl AKepoll_wait
AKepoll_create:
	pushl	%ebp
	movl	%esp,%ebp
	addl	$4,%ebp
	pushl	%ebx

	movl	4(%ebp),%ebx #size
	movl	$254,%eax #__NR_epoll_create
	int	$0x80

	popl	%ebx
	popl	%ebp
	ret
AKepoll_ctl:
	pushl	%ebp
	movl	%esp,%ebp
	addl	$4,%ebp
	pushl	%ebx
	pushl	%ecx
	pushl	%edx
	pushl	%esi

	movl	4(%ebp),%ebx #epfd
	movl	8(%ebp),%ecx #op
	movl	12(%ebp),%edx #fd
	movl	16(%ebp),%esi #event
	movl	$255,%eax #__NR_epoll_ctl
	int	$0x80

	popl	%esi
	popl	%edx
	popl	%ecx
	popl	%ebx
	popl	%ebp
	ret
AKepoll_wait:
	pushl	%ebp
	movl	%esp,%ebp
	addl	$4,%ebp
	pushl	%ebx
	pushl	%ecx
	pushl	%edx
	pushl	%esi

	movl	4(%ebp),%ebx #epfd
	movl	8(%ebp),%ecx #events
	movl	12(%ebp),%edx #maxevents
	movl	16(%ebp),%esi #timeout
	movl	$256,%eax #__NR_epoll_wait
	int	$0x80

	popl	%esi
	popl	%edx
	popl	%ecx
	popl	%ebx
	popl	%ebp
	ret
