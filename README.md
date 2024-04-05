# DSE & PG bypass via BYOVD attack

+ Обход Driver Signature Enforcement и Patch Guard через BYOVD атаку
+ Данный подход предствлен в образовательных целях (For Educational Purpose)

## WriteUP Reversing Signature Validation

+ Функции ядра Windows, участвующие в валидации image (driver) PE
+ Интересущие методы, приведенные указатели функций, возвращающие NTSTATUS
+ `qword_140C375A0` и `qword_140C375С8`

```C++
__int64 __fastcall SeValidateImageHeader(
        __int64 a1,
        __int64 a2,
        __int64 a3,
        __int64 a4,
        int a5,
        __int64 a6,
        __int64 a7,
        __int64 a8,
        __int64 a9,
        char a10)
{
  if ( qword_140C375A0 )
  {
    if ( (a10 & 1) != 0 )
      _InterlockedCompareExchange(&dword_140D0C720, 0, 0);
    return (unsigned int)((__int64 (__fastcall *)(__int64, __int64))qword_140C375A0)(a1, a2);
  }
  else
  {
    return (unsigned int)-1073740760; //0x0C0000428 STATUS_INVALID_IMAGE_HASH
  }
}

// Представление SeValidateImageHeader в WinDBG 
nt!SeValidateImageHeader:
fffff801`170f2b98 488bc4          mov     rax,rsp
fffff801`170f2b9b 48895808        mov     qword ptr [rax+8],rbx
fffff801`170f2b9f 48897010        mov     qword ptr [rax+10h],rsi
fffff801`170f2ba3 57              push    rdi
fffff801`170f2ba4 4881eca0000000  sub     rsp,0A0h
fffff801`170f2bab 33f6            xor     esi,esi
fffff801`170f2bad 488bda          mov     rbx,rdx
// нас интересует данный callback
fffff801`170f2bb0 483935e9495400  cmp     qword ptr [nt!SeCiCallbacks+0x20 (fffff801`17a375a0)],rsi // адресация на qword_140C375A0 -> RVA 0xc375a0
...................................................
```

```C++
__int64 __fastcall SeValidateImageData(__int64 a1)
{
  if ( qword_140C375С8 )
    return qword_140C375С8(a1);
  else
    return 3221226536i64; //0x0C0000428 STATUS_INVALID_IMAGE_HASH
}

// Представление SeValidateImageData в WinDBG 
nt!SeValidateImageData:
fffff802`17086b0c 4883ec48        sub     rsp,48h
// нас интересует данный callback
fffff802`17086b10 488b05b10a5b00  mov     rax,qword ptr [nt!SeCiCallbacks+0x28 (fffff802`176375c8)] // адресация на qword_140C375C8 -> RVA 0xc375c8
fffff802`17086b17 4c8bd1          mov     r10,rcx
fffff802`17086b1a 4885c0          test    rax,rax
fffff802`17086b1d 7420            je      nt!SeValidateImageData+0x33 (fffff802`17086b3f)
...................................................
```

## WriteUP Reversing PatchGuard

+ PatchGuard работает на контекстах

```C++
nt!KiFilterFiberContext+0x1b00:
fffff802`17517730 4c894c2420      mov     qword ptr [rsp+20h],r9
fffff802`17517735 4489442418      mov     dword ptr [rsp+18h],r8d
fffff802`1751773a 894c2408        mov     dword ptr [rsp+8],ecx
fffff802`1751773e 53              push    rbx
fffff802`1751773f 56              push    rsi
fffff802`17517740 57              push    rdi
fffff802`17517741 4154            push    r12
fffff802`17517743 4155            push    r13
fffff802`17517745 4156            push    r14
fffff802`17517747 4157            push    r15
fffff802`17517749 4881ec60220000  sub     rsp,2260h
fffff802`17517750 498bc1          mov     rax,r9
fffff802`17517753 8bf2            mov     esi,edx
fffff802`17517755 fa              cli
fffff802`17517756 33c9            xor     ecx,ecx

// Нас интересует данная проверка на наличие отладчика
fffff802`17517758 380d2b341400    cmp     byte ptr [nt!KdDebuggerNotPresent (fffff802`1765ab89)],cl

// Если отладчика нет - поток выполняется далее
fffff802`1751775e 7502            jne     nt!KiFilterFiberContext+0x1b32 (fffff802`17517762)

// Если отладчик есть - в бесконечный цикл
nt!KiFilterFiberContext+0x1b30:
fffff802`17517760 ebfe            jmp     nt!KiFilterFiberContext+0x1b30 (fffff802`17517760)

...................................................

// PS: весь код данной функции сильно обфусцирован (далее фрагмент с junk кодом)
!KiFilterFiberContext+0x1b4e:
fffff802`1751777e 8d46fd          lea     eax,[rsi-3]
fffff802`17517781 a9fdffffff      test    eax,0FFFFFFFDh
fffff802`17517786 7504            jne     nt!KiFilterFiberContext+0x1b5c (fffff802`1751778c)  

nt!KiFilterFiberContext+0x1b58:
fffff802`17517788 33c0            xor     eax,eax
fffff802`1751778a 8bf0            mov     esi,eax

nt!KiFilterFiberContext+0x1b5c:
fffff802`1751778c 8b8424c0220000  mov     eax,dword ptr [rsp+22C0h]
fffff802`17517793 eb18            jmp     nt!KiFilterFiberContext+0x1b7d (fffff802`175177ad)  

nt!KiFilterFiberContext+0x1b65:
fffff802`17517795 413bf7          cmp     esi,r15d
fffff802`17517798 7705            ja      nt!KiFilterFiberContext+0x1b6f (fffff802`1751779f)  

nt!KiFilterFiberContext+0x1b6a:
fffff802`1751779a 0fa3f2          bt      edx,esi
fffff802`1751779d 7204            jb      nt!KiFilterFiberContext+0x1b73 (fffff802`175177a3)  

nt!KiFilterFiberContext+0x1b6f:
fffff802`1751779f 33c0            xor     eax,eax
fffff802`175177a1 8bf0            mov     esi,eax

nt!KiFilterFiberContext+0x1b73:
fffff802`175177a3 8b8424c0220000  mov     eax,dword ptr [rsp+22C0h]
fffff802`175177aa 410bc5          or      eax,r13d

nt!KiFilterFiberContext+0x1b7d:
fffff802`175177ad 89842498030000  mov     dword ptr [rsp+398h],eax
fffff802`175177b4 83fe07          cmp     esi,7
fffff802`175177b7 7453            je      nt!KiFilterFiberContext+0x1bdc (fffff802`1751780c)  

nt!KiFilterFiberContext+0x1b89:
fffff802`175177b9 e842c30700      call    nt!KiAreCodePatchesAllowed (fffff802`17593b00)
fffff802`175177be 85c0            test    eax,eax
fffff802`175177c0 744a            je      nt!KiFilterFiberContext+0x1bdc (fffff802`1751780c)  

nt!KiFilterFiberContext+0x1b92:
fffff802`175177c2 e821d20400      call    nt!KiSwInterruptPresent (fffff802`175649e8)
fffff802`175177c7 85c0            test    eax,eax
fffff802`175177c9 7841            js      nt!KiFilterFiberContext+0x1bdc (fffff802`1751780c)  

nt!KiFilterFiberContext+0x1b9b:
fffff802`175177cb e858b00100      call    nt!KiFilterFiberContext+0x1cbf8 (fffff802`17532828)
fffff802`175177d0 85c0            test    eax,eax
fffff802`175177d2 7438            je      nt!KiFilterFiberContext+0x1bdc (fffff802`1751780c)  

nt!KiFilterFiberContext+0x1ba4:
fffff802`175177d4 e873c30700      call    nt!KiGetLoadOptions (fffff802`17593b4c)
fffff802`175177d9 488d15c0bb0500  lea     rdx,[nt! ?? ::PBOPGDP::`string' (fffff802`175733a0)]
fffff802`175177e0 488bc8          mov     rcx,rax
fffff802`175177e3 488bd8          mov     rbx,rax
fffff802`175177e6 e875f18bff      call    nt!strstr (fffff802`16dd6960)
fffff802`175177eb 4885c0          test    rax,rax
fffff802`175177ee 751c            jne     nt!KiFilterFiberContext+0x1bdc (fffff802`1751780c)  
...................................................
```

## BYOVD attack

+ используется уязвимый драйвер AMD `PdFwKrnl`
+ используется примитив `memcpy` from virtual to physical memory

## Пример работы

+ тестовая система Windows 11 версии 10.0.22631.3374 с последними обновлениями

![alt text](/img/dse_pg_bypass.gif)

## Ссылки

+ [LolDriver PoC](https://github.com/TakahiroHaruyama/VDR/tree/main/PoCs/firmware/eop_pdfwkrnl.py)
+ [LolDriver Link](https://www.loldrivers.io/drivers/fded7e63-0470-40fe-97ed-aa83fd027bad/)
+ [PatchGuard Article](https://habr.com/ru/companies/pt/articles/246841/)
+ [PatchNtoskrnl](https://github.com/Mattiwatti/EfiGuard/blob/25bb182026d24944713e36f129a93d08397de913/EfiGuardDxe/PatchNtoskrnl.c)
