[BITS 64]

global WinMain

section .text
WinMain:
    Start:
        ;***************
        ;**** START ****
        ;***************
        ;* By: Teuzero *
        ;***************

        add rsp, 0xfffffffffffffdf8; # Avoid Null Byte
        ; Obtem o endereço base do kernel32.dll 
        call Locate_kernel32
        call IAT
        call FinFunctionGetProcAddress
        call LoadLibraryA
        call LoadMsvcrt
        call PrintMsgConsole
        call PegaNomeDoaquivo
        call OpenFile
        mov rbp,rdi
        ret


        IAT:
        ; Código para chegar na tabela de endereco de exportacao
        mov ebx, [rbx+0x3C];  # obtem o endereco da assinatura do  PE do Kernel32 e coloca em  EBX
        add rbx, r8;          # Add defrerenced signature offset to kernel32 base. Store in RBX.
        mov r12, 0x88FFFFF;      
        shr r12, 0x14; 
        mov edx, [rbx+r12];   # Offset from PE32 Signature to Export Address Table (NULL BYTE)
        add rdx, r8;          # RDX = kernel32.dll + RVA ExportTable = ExportTable Address
        mov r10d, [rdx+0x14]; # numero de funcoes
        xor r11, r11;         # Zera R11 para ser usado 
        mov r11d, [rdx+0x20]; # AddressOfNames RVA
        add r11, r8;          # AddressOfNames VMA
        ret

        ; Percorra a tabela de endereços de exportação para encontrar o nome GetProcAddress
        FinFunctionGetProcAddress:
        mov rcx, r10;                        # Set loop counter
        kernel32findfunction:  
                jecxz FunctionNameFound;     # Percorra esta função até encontrarmos GetProcA
                xor ebx,ebx;                 # Zera EBX para ser usada
                mov ebx, [r11+4+rcx*4];      # EBX = RVA para o primeiro AddressOfName
                add rbx, r8;                 # RBX = Nome da funcao VMA
                dec rcx;                     # Decrementa o loop em 1
                mov rax, 0x41636f7250746547; # GetProcA
                cmp [rbx], rax;              # checa se rbx é igual a  GetProcA
                jnz kernel32findfunction;  
        
        ; Encontra o endereço da função de GetProcessAddress
        FunctionNameFound:                 
                ; We found our target
                xor r11, r11; 
                mov r11d, [rdx+0x24];   # AddressOfNameOrdinals RVA
                add r11, r8;            # AddressOfNameOrdinals VMA
                ; Get the function ordinal from AddressOfNameOrdinals
                inc rcx; 
                mov r13w, [r11+rcx*2];  # AddressOfNameOrdinals + Counter. RCX = counter
                ; Get function address from AddressOfFunctions
                xor r11, r11; 
                mov r11d, [rdx+0x1c];   # AddressOfFunctions RVA
                add r11, r8;            # AddressOfFunctions VMA in R11. Kernel32+RVA for addressoffunctions
                mov eax, [r11+4+r13*4]; # Get the function RVA.
                add rax, r8;            # Add base address to function RVA
                mov r14, rax;           # GetProcAddress to R14
        ret

        LoadLibraryA:
               ; pega o endereco LoadLibraryA usando GetProcAddress
                mov rcx, 0x41797261;  
                push rcx;  
                mov rcx, 0x7262694c64616f4c;  
                push rcx;  
                mov rdx, rsp;                      # joga o ponteiro da string LoadLibraryA para RDX
                mov rcx, r8;                       # Copia o endereço base da Kernel32  para RCX
                sub rsp, 0x30;                     # Make some room on the stack
                call r14;                          # Call GetProcessAddress
                add rsp, 0x30;                     # Remove espaço locdo na pilha
                add rsp, 0x10;                     # Remove a string alocada de  LoadLibrary 
                mov rsi, rax;                      # Guarda o endereço de loadlibrary em RSI
        ret

        LoadMsvcrt:
                ; Load msvcrt.dll
                mov rax, "ll"
                push rax
                mov rax, "msvcrt.d"
                push rax
                mov rcx, rsp
                sub rsp, 0x30
                call rsi
                mov r15,rax
                add rsp, 0x30
                add rsp, 0x10
        ret

        PrintMsgConsole:
                ; Lookup printf
                mov rax, "printf"
                push rax
                mov rdx, rsp
                mov rcx, r15
                sub rsp, 0x30
                call r14
                add rsp, 0x30
                mov r12, rax
        
                ; call printf
                mov rax, ":"
                push rax
                mov rax, "[+] File"
                push rax
                lea rcx, [rsp]
                sub rsp, 0x30
                call r12
                add rsp, 0x30
                add rsp, 0x18
        ret

        PegaNomeDoaquivo:
                ; Lookup scanf
                mov rax, "scanf"
                push rax
                mov rdx,rsp
                mov rcx, r15
                sub rsp, 0x30
                call r14
                mov r12, rax
                add rsp, 0x30
            
                ; call scanf
                lea rax, [rsp+0x20]
                mov rdx, rax
                mov rax, "%s"
                push rax
                lea rcx, [rsp]
                sub rsp, 0x30
                call r12
                add rsp, 0x30
                add rsp, 0x10
        ret

        OpenFile:
                ;Lookup fopen
                mov rax, "fopen"
                push rax
                lea rdx, [rsp]
                mov rcx, r15
                sub rsp, 0x30
                call r14
                mov r12,rax
                add rsp, 0x30
        
                ;Abre arquivo
                lea rcx, [rsp+0x20]
                mov rax, "rb"
                push rax
                lea rdx, [rsp]
                sub rsp, 0x30
                call r12
                add rsp, 0x30
                mov rbx,rax
                add rsp, 0x10
        

        LocomoveParaOFimDoarquivo:
                ;Lookup fseek
                mov rax, "fseek"
                push rax
                lea rdx, [rsp]
                mov rcx, r15
                sub rsp, 0x30
                call r14
                mov r12,rax
                add rsp, 0x30

                ;call fseek
                mov rcx, rbx
                mov r8d, dword 0x02        
                mov edx, dword 0x00
                sub rsp, 0x30
                call r12
                add rsp, 0x30
                add rsp, 0x08
        
        GetSizeFile:
                ;Lookup ftell
                mov rax, "ftell"
                push rax
                lea rdx, [rsp]
                mov rcx, r15
                sub rsp, 0x30
                call r14
                add rsp, 0x30
                mov r12,rax
        
                ;call ftell
                mov rcx, rbx
                sub rsp, 0x30
                call r12
                add rsp,0x30
                mov rsi,rax
                add rsp, 0x08

        AlocaEspacoEmUmEndereco:
                ;Lookup malloc
                mov rax, "malloc"
                push rax
                lea rdx, [rsp]
                mov rcx, r15
                sub rsp, 0x30
                call r14
                mov r12,rax
                add rsp, 0x30

                ;call malloc
                mov rcx, rsi
                sub rsp, 0x30
                call r12
                mov rdi, rax
                add rsp,0x30
                add rsp, 0x08

        MoveParaInicioDoArquivo:
                ;Lookup rewind
                mov rax, "rewind"
                push rax
                lea rdx, [rsp]
                mov rcx, r15
                sub rsp, 0x30
                call r14
                mov r12, rax
                add rsp, 0x30
        
                ;call rewind
                mov rcx, rbx
                sub rsp, 0x30
                call r12
                add rsp, 0x30
                add rsp, 0x08

        GravaOPEdoArquivoNoEnderecoAlocadoPorMalloc:
                ;Lookup fread
                mov rax, "fread"
                push rax
                lea rdx, [rsp]
                mov rcx, r15
                sub rsp, 0x30
                call r14
                mov r12, rax
                add rsp, 0x30

                ;call fread
                mov edx,esi
                mov r9, rbx
                mov r8d, 0x01
                mov rcx, rdi
                sub rsp, 0x30
                call r12
                add rsp, 0x30
                add rsp, 0x08

        FechaArquivo:
                ;Lookup fclose
                mov rax, "fclose"
                push rax
                lea rdx, [rsp]
                mov rcx, r15
                sub rsp, 0x30
                call r14
                mov r12, rax
                add rsp, 0x30

                ;call fclose
                sub rsp,0x30
                mov rcx, rbx
                call r12
                add rsp, 0x30
                add rsp, 0x08
        ret
        
            
        ;locate_kernel32
        Locate_kernel32: 
                xor rcx, rcx;             # Zera RCX
                mov rax, gs:[rcx + 0x60]; # 0x060 ProcessEnvironmentBlock to RAX.
                mov rax, [rax + 0x18];    # 0x18  ProcessEnvironmentBlock.Ldr Offset
                mov rsi, [rax + 0x20];    # 0x20 Offset = ProcessEnvironmentBlock.Ldr.InMemoryOrderModuleList
                lodsq;                    # Load qword at address (R)SI into RAX (ProcessEnvironmentBlock.Ldr.InMemoryOrderModuleList)
                xchg rax, rsi;            # troca RAX,RSI
                lodsq;                    # Load qword at address (R)SI into RAX
                mov rbx, [rax + 0x20] ;   # RBX = Kernel32 base address
                mov r8, rbx;              # Copia o endereco base do Kernel32 para o registrador R8
                ret
        

        ;locate_ntdll
        Locate_ntdll:        
                xor rcx, rcx;             # Zera RCX
                mov rax, gs:[rcx + 0x60]; # 0x060 ProcessEnvironmentBlock to RAX.
                mov rax, [rax + 0x18];    # 0x18  ProcessEnvironmentBlock.Ldr Offset
                mov rsi, [rax + 0x30];    # 0x30 Offset = ProcessEnvironmentBlock.Ldr.InInitializationOrderModuleList
                mov rbx, [rsi +0x10];     # dll base ntdll
                mov r8, rbx;              # Copia o endereco base da ntdll para o registrador R8
        ret                         
ret
