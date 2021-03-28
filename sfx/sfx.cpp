// (c) Peter Kankowski, 2006 http://smallcode.weblogs.us kankowski@narod.ru
#include <windows.h>
#include <stdint.h>
#include <zip.h>
#include <zipconf.h>
#include <cstdio>


FILE *fd;

// ****        Reading from exe file        ****
const int ERR_OK = 0, ERR_READFAILED = 1, ERR_NOINFO = 2, ERR_BADFORMAT = 3;
int ProcessData(char* data, int datasize) {
	zip_source_t *src;
	zip_error_t error;
	zip_stat_t sb;
	zip_file_t *zf;
	zip_t *za;

	zip_error_init(&error);

	if ((src = zip_source_buffer_create(data, datasize, 1, &error)) == NULL) {
		fprintf(stderr, "can't create source: %s\n", zip_error_strerror(&error));
		free(data);
		zip_error_fini(&error);
		return 1;
	}
	if ((za = zip_open_from_source(src, 0, &error)) == NULL) {
		fprintf(stderr, "can't open zip from source: %s\n", zip_error_strerror(&error));
		zip_source_free(src);
		zip_error_fini(&error);
		return 1;
	}

	for (int i = 0; i < zip_get_num_entries(za, 0); i++) {
		if (zip_stat_index(za, i, 0, &sb) == 0) {
			printf("==================\n");
			printf("Name: [%s], ", sb.name);
			printf("Size: [%llu], ", sb.size);
			printf("mtime: [%u]\n", (unsigned int)sb.mtime);
				zf = zip_fopen(za, sb.name, 0);
				if (!zf) {
					printf("error open file in archive. Error NO: %llu\n",(uint64_t)zf);
				}
				char file[255];
				char *ptr; 
				size_t tmplen;
				errno_t errors = _dupenv_s(&ptr, &tmplen, "TEMP");
				if(errors)printf("Path error %d\n", errors);
				if (tmplen > 255) {
					printf("Path too long");

				}
				memcpy(file, ptr, tmplen);
				free(ptr);
				strncat_s(file, "\\", 255);
				strncat_s(file, sb.name, 255);
				printf(file);

				int err = fopen_s(&fd, file, "w+");
				printf("cant open file %d \n",err);

				if (!err) {
					printf("cant open file");
				}
				char buf[1024];
				uint64_t sum = 0;
				while (sum != sb.size) {
					uint64_t len = (uint64_t) zip_fread(zf, buf, 1024);
					if (len < 0) {
						printf("cant read from archived file Error No: %llu\n",len);
					}
					fwrite(buf, 1,len,fd);
					sum += len;
				}
				fclose(fd);
				zip_fclose(zf);
			}
	}
	char file[255];
	char *ptr;
	size_t tmplen;
	errno_t errors = _dupenv_s(&ptr, &tmplen, "TEMP");
	if (errors)printf("Path error %d\n", errors);
	if (tmplen > 255) {
		printf("Path too long");

	}
	memcpy(file, ptr, tmplen);
	free(ptr);
	strncat_s(file, "\\install.bat", 255);

	printf(file);
	system(file);

	for (int i = 0; i < zip_get_num_entries(za, 0); i++) {
		if (zip_stat_index(za, i, 0, &sb) == 0) {
			char file[255];
			char *ptr;
			size_t tmplen;
			errno_t errors = _dupenv_s(&ptr, &tmplen, "TEMP");
			if (errors)printf("Path error %d\n", errors);
			if (tmplen > 255) {
				printf("Path too long");

			}
			memcpy(file, ptr, tmplen);
			free(ptr);
			strncat_s(file, "\\", 255);
			strncat_s(file, sb.name, 255);
			if (remove(file) == 0)
				printf("Deleted successfully\n");
			else
				printf("Unable to delete the file\n");
		}
	}

	/* close archive */
	if (zip_close(za) < 0) {
		fprintf(stderr, "can't close zip archive '%s\n", zip_strerror(za));
		return 1;
	}
	//free(data); //huh 
	//zip_source_free(src);
	
	return 0;
}

int ReadFromExeFile(char* data,int* size) {
	/* Reads data attached to the exe file and calls
	   ProcessData(pointertodata, datasize).
	   Return values:
		  * ERR_READFAILED - read from exe file had failed;
		  * ERR_BADFORMAT  - invalid format of the exe file;
		  * ERR_NOINFO     - no info was attached.
	   If the data were read OK, it returns the return value of ProcessData.
	*/
#define ErrIf(a) if(a){\
		CloseHandle(hFile);\
		return ERR_BADFORMAT;\
	}
	BYTE buff[4096]; DWORD read; 

	// Open exe file
	GetModuleFileName(NULL, (LPWSTR)buff, sizeof(buff));
	HANDLE hFile = CreateFile((LPWSTR)buff, GENERIC_READ, FILE_SHARE_READ,
		NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (INVALID_HANDLE_VALUE == hFile) return ERR_READFAILED;
	if (!ReadFile(hFile, buff, sizeof(buff), &read, NULL)) {
		CloseHandle(hFile);
		return ERR_READFAILED;
	}
	IMAGE_DOS_HEADER* dosheader = (IMAGE_DOS_HEADER*)buff;
	ErrIf(dosheader->e_magic != IMAGE_DOS_SIGNATURE);
	ErrIf(ULONG(dosheader->e_lfanew) >= ULONG(sizeof(buff) - sizeof(IMAGE_NT_HEADERS32)));

	// Locate PE header
	IMAGE_NT_HEADERS32* header = (IMAGE_NT_HEADERS32*)(buff + dosheader->e_lfanew);

	ErrIf(header->Signature != IMAGE_NT_SIGNATURE);
	IMAGE_SECTION_HEADER* sectiontable = IMAGE_FIRST_SECTION(header);
	ErrIf((BYTE*)sectiontable >= buff + sizeof(buff));
	DWORD maxpointer = 0, exesize = 0;
	// For each section
	for (int i = 0; i < header->FileHeader.NumberOfSections; ++i) {
		if (sectiontable->PointerToRawData > maxpointer) {
			maxpointer = sectiontable->PointerToRawData;
			exesize = sectiontable->PointerToRawData + sectiontable->SizeOfRawData;
		}
		sectiontable++;
	}
	// Seek to the overlay
	DWORD filesize = GetFileSize(hFile, NULL);
	printf("%u %u\n", filesize, exesize);
	if (exesize == filesize) {
		CloseHandle(hFile);
		return ERR_NOINFO;
	}
	ErrIf(filesize == INVALID_FILE_SIZE || exesize > filesize);
	data = (char*)malloc(filesize - exesize + 8);
	if (SetFilePointer(hFile, exesize, NULL, FILE_BEGIN) == INVALID_SET_FILE_POINTER) {
		CloseHandle(hFile);
		return ERR_READFAILED;
	}
	if (!ReadFile(hFile, data, filesize-exesize, &read, NULL)) {
		free(data);
		CloseHandle(hFile);
		return ERR_READFAILED;
	} else {
		CloseHandle(hFile);

		// Process the data
		*size = (int)filesize - (int)exesize;
		int err = ProcessData(data, *size);
		return err;
	}

#undef ErrIf
}

int main(){
	int err = 0;
	char* data = nullptr;
	int size = 0;
	if ((err = ReadFromExeFile(data,&size)) == ERR_OK) {

	}
	printf("%d", err);
	return err;
}
