/*
SCANNER.C
This software is used to scan the windows' registry in search for hardware
and software informations, then store the informations into a MySQL
database. It reads a simple configuration file and scan the registry in
search of the keys mentioned in the config file.

ATTENTION: this program is free software, so it came with _ABSOLUTE_
NO WARRANTY! I'm not responsable if this software erase your hard disk,
empty your bank account, stole your car, destroy your furnitures, set
your house in fire, seduces your wife and kill your dog.
*/

#include <conio.h>
#include <stdio.h>
#include <windows.h>
#include <winioctl.h>
#include <winreg.h>
#include <mysql.h>

#define MAX_HKEY_LENGTH 255
#define MAX_VALUE_NAME 16383
#define MAXLINE 256

#define COMPUTERNAME "SYSTEM\\CurrentControlSet\\Control\\ComputerName\\ComputerName"

void getcomputername(char*);

void getthefuckingmemory(void);
int  readconfig(char*);
int  scansubkeys(HKEY, char *[]);
int  scanvalues(HKEY, char *[]);
void scanakey(HKEY, char*, char*);
void scanallofthem(char*);
void storedata(char*,char*,char*);
void strtran(char*,char*,char,char);
void getthedisks(void);
BOOL getdisksize(DISK_GEOMETRY*,int);

/* Yes, I know that I shouldn't use global variables. */
char dbserver[MAXLINE],dbuser[MAXLINE];
char dbpass[MAXLINE],dbtable[MAXLINE];
char *_keys[MAXLINE];
char cname[MAXLINE];
int keynum=0;
int status=0;
char query[4096];

/* global connection to MySQL */
MYSQL *mysql;

/* main */
int main(int argc, char *argv[]) {

	printf("Hardware Software Scanner V.1.1\n");
	printf("Now scanning your system ");
	if(argc>1) {

		readconfig(argv[1]);
		getcomputername(cname);

		/* initialize connection */
		mysql=mysql_init(NULL);

		if(!mysql_real_connect(mysql,dbserver,dbuser,
			dbpass,dbtable,0,NULL,0)) {
			return 1;
		}

		/* clean up database */
		sprintf(query,"delete from profiles where computer='%s'",cname);
		if(mysql_query(mysql,query)) {
			return 1;
		}

		/* get the information from the machine */
		getthefuckingmemory();
		getthedisks();
		scanallofthem(cname);

		/* ok, done */
		mysql_close(mysql);

	}
	printf(" done.\n");
	return 0;
} 

/* scan all the subkeys for a specific key, return the number of
   subkeys found, the keys are stored in the array.
*/
int scansubkeys(HKEY key, char *keys[]) {

	CHAR     keyname[MAX_HKEY_LENGTH];
	DWORD    namesize;
	CHAR     classname[MAX_PATH] = "";
	DWORD    classnamesize = MAX_PATH;
	DWORD    subkeys=0;
	DWORD    longestsubkey;
	DWORD    longestclass;
	DWORD    values;
	DWORD    longestvalue;
	DWORD    longestvaluedata;
	DWORD    securitydescr;
	FILETIME lastwritetime;
	DWORD 	 i, ret;

	/* Get the class name and the value count. */
	ret = RegQueryInfoKey(key,classname,&classnamesize,NULL,&subkeys,
        	&longestsubkey,&longestclass,&values,&longestvalue,
		&longestvaluedata, &securitydescr,&lastwritetime);

	if(ret!=0) {
		return 0;
	}
 
	if (subkeys) {
	        for (i=0; i<subkeys; i++) { 
			namesize = MAX_HKEY_LENGTH;
			ret = RegEnumKeyEx(key, i, keyname, &namesize, NULL,
				NULL, NULL, &lastwritetime);

			if (ret == ERROR_SUCCESS) {
				keys[i]=calloc(namesize+1,sizeof(char));
				strcpy(keys[i],keyname);
			}
		}
	}

	return subkeys;
}

/* scan all the values for a specific key, return the number of
   values, the values are stored in the array

NOTE: the values I'm interested into are strings and decimals, so I
just throw away everything else.

*/
int scanvalues(HKEY key, char *val[]) {

	DWORD    values;
	DWORD    longestvalue;
	DWORD    longestvaluedata;
	DWORD 	 i, ret;
	CHAR     achValue[MAX_VALUE_NAME]; 
	DWORD    cchValue = MAX_VALUE_NAME;
	DWORD	 datatype=0;
	CHAR     datavalue[MAX_VALUE_NAME];
	DWORD	 tdata;
	DWORD    datavaluesize = MAX_VALUE_NAME;

	ret = RegQueryInfoKey(key,NULL,NULL,NULL,NULL,
        	NULL,NULL,&values,&longestvalue,
		&longestvaluedata,NULL,NULL);

	if(ret!=0) {
		return 0;
	}
 
	if(values) {
		for (i=0; i<values; i++) { 
			cchValue = MAX_VALUE_NAME; 
			achValue[0] = '\0'; 
			datavaluesize = MAX_VALUE_NAME;
			datavalue[0] = '\0';

			ret = RegEnumValue(key, i, achValue, &cchValue, NULL, 
				&datatype, datavalue, &datavaluesize);

			if(ret == ERROR_SUCCESS) {

				val[i] = malloc(MAX_VALUE_NAME);

				switch(datatype) {
				case REG_SZ:
					sprintf(val[i],
						"%s;%s\0",
						achValue,
						datavalue);
					break;

				case REG_DWORD:
					cchValue = MAX_VALUE_NAME; 
					achValue[0] = '\0'; 
					tdata=0;
					datavaluesize = MAX_VALUE_NAME;

					RegEnumValue(key, i, achValue, 
						&cchValue, NULL, &datatype,
						&tdata, &datavaluesize);
					sprintf(val[i],"%s;%d\0",
						achValue,tdata);
					break;

				default:
					/* if it isn't a string or a decimal
					I don't want it. */
					sprintf(val[i],"%s;%d\0",achValue,0);
				}
			}
		}
	}

	return values;
}

/* this is specific to get the computer name from the machine so we can use it
   later to store all the data under the computer name itself.
*/
void getcomputername(char *cname) {

	HKEY key;
	int i,numval;
	char *val[2];	/* why 2? just to be safe */
	char *p;

	if(RegOpenKey(HKEY_LOCAL_MACHINE,COMPUTERNAME,&key) != 0) {
		return;
	}

	/* scan the values */
	numval=scanvalues(key,val);
	if(numval) {
		for(i=0;i<numval;i++) {
			sprintf(cname,val[i]);
		}
	}

	p=strtok(cname,";");
	p=strtok(NULL,";");
	strcpy(cname,p);

	/* release the memory */
	for(i=0;i<numval;i++) {
		free(val[i]);
	}

	/* close the registry */
	RegCloseKey(key);
	return;
}

/* scan all the keys and store the data */
void scanallofthem(char *cname) {

	HKEY key;
	char *val[2048];
	char temp[1024];
	int i,j,numval;

	for(i=0;i<keynum;i++) {
		if(strncmp(_keys[i],"*",1)==0) {
			strcpy(temp,_keys[i]+1);
			if(RegOpenKey(HKEY_LOCAL_MACHINE,temp,&key) != 0) {
				return;
			}
			scanakey(key,temp,cname);
			RegCloseKey(key);
		} else {
			if(RegOpenKey(HKEY_LOCAL_MACHINE,_keys[i],&key) != 0) {
				return;
			}
			numval=scanvalues(key,val);
			for(j=0;j<numval;j++) {
				/* insert the data in the database */
				storedata(cname,_keys[i],val[j]);
				free(val[j]);
			}
			RegCloseKey(key);
		}
	}
	return;
}

/* scan a key, call storedata to store the information in the database
this is actually a recursive function that call herself to scan all
the subkeys for a key.
*/
void scanakey(HKEY key, char *keyname, char *cname) {

	HKEY subkey;
	int i,j,numval,numkeys;
	char *val[1024];
	char *keys[4096];
	char currentkey[4096];

	/* scan the values of this key */
	numval=scanvalues(key,val);
	for(j=0;j<numval;j++) {
		storedata(cname, keyname, val[j]);
		free(val[j]);
	}

	/* scan the subkeys of this key */
	numkeys=scansubkeys(key,keys);
	for(i=0;i<numkeys;i++) {
		sprintf(currentkey,"%s\\%s",keyname,keys[i]);
		if(RegOpenKey(HKEY_LOCAL_MACHINE,currentkey,&subkey) != 0) {
			return;
		}
		scanakey(subkey,currentkey,cname);
		RegCloseKey(subkey);
	}
	return;
}

/* read the configuration file */
int readconfig(char *configfile) {

	FILE *infile;
	char ch[2];
	char line[MAXLINE];
	char *element, *value;
	int i=0;

	/* try to open the configuration file */
	infile=fopen(configfile,"r");
	if(infile==NULL) {
		printf("Error opening %s.\n",configfile);
		return 1;
	}

	/* loop and read the file */
	while(fread(ch,1,1,infile)==1) {

		if(ch[0]!='\n') {
			line[i]=ch[0];
			i++;
		} else {
			line[i]='\0';

			/* check if the line is a directive */
			if(line[0]!='#' && line[0]!='\0') {

				element=strtok(line,"=");
				value=strtok(NULL,"=");

				if(strcmp(element,"dbserver")==0) {
					strcpy(dbserver,value);
				}
				if(strcmp(element,"dbuser")==0) {
					strcpy(dbuser,value);
				}
				if(strcmp(element,"dbpass")==0) {
					strcpy(dbpass,value);
				}
				if(strcmp(element,"dbtable")==0) {
					strcpy(dbtable,value);
				}

				/* copy the key */
				if(strcmp(element,"key")==0) {
					_keys[keynum]=malloc(strlen(value)+1);
					strcpy(_keys[keynum],value);
					keynum++;
				}
			}
			i=0;
		}
	}

	fclose(infile);
	return 0;
}

/* store the data in the database */
void storedata(char *cname, char *keyname, char *val) {

	char *p;
	unsigned int i;
	int first=0;
	char kname[150];
	char valname[1024];

	/* if the value is "0", I don't want it. */
	if(strcmp(val,"0")==0) {
		return;
	}

	memset(valname,0,1024);
	memset(kname,0,150);
	
	/* convert unwanted chars */
	strtran(kname,keyname,'\\','/');
	strtran(kname,kname,'"',' ');
	strtran(valname,val,'\\','/');
	strtran(valname,valname,'"',' ');

	/* trim down the Keyname */
	for(i=0;i<strlen(kname);i++) {
		if(kname[i]=='/') {
			p=&kname[i];
			break;
		}
	}
	for(i=strlen(kname);i>0;i--) {
		if(kname[i]=='/') {
			strcpy(p,&kname[i]);
			break;
		}
	}

	/* get the value id and value from the 'value' block */
	/* I don't know why but I can't use strtok here! */
	for(i=0;i<strlen(valname);i++) {
		if(valname[i]==';') {
			p=&valname[i]+1;
			valname[i]='\0';
			break;
		}
	}

#ifdef _DEBUG
	printf("%s-[%s] [%s] %s\n",cname,kname,valname,p);
#else
	sprintf(query,
		"insert into profiles (computer,keyid,valid,value) \
		values ('%s',\"%s\",\"%s\",\"%s\")",
		cname,kname,valname,p);
	mysql_query(mysql,query);

	status++;
	if(status==10) {
		status=0;
		printf(".");
	}
#endif

	return;
}

/* used to translates chars like '\' and ' itself. */
void strtran(char *dest, char *orig, char ch,char n) {

	unsigned int i;
	for(i=0;i<strlen(orig);i++) {
		if(orig[i]==ch) {
			dest[i]=n;
		} else {
			dest[i]=orig[i];
		}
	}
	return;
}

/* since I couldn't find a way to get the RAM from the registry, I cheated!
*/
void getthefuckingmemory() {

	char val[120];
	unsigned long totmem;
	MEMORYSTATUS stat;

	GlobalMemoryStatus(&stat);
	totmem=stat.dwTotalPhys/1024;
	sprintf(val,"PhysicalMemory;%ld",totmem);
	storedata(cname,"HARDWARE/DESCRIPTION/System/Memory",val);
	return;

}

BOOL getdisksize(DISK_GEOMETRY *pdg,int diskid) {

	HANDLE disk;
	BOOL result;
	DWORD junk;
	char phdisk[50];

	sprintf(phdisk,"\\\\.\\PhysicalDrive%d\0",diskid);

	disk = CreateFile(phdisk,0,FILE_SHARE_READ | FILE_SHARE_WRITE,
			NULL,OPEN_EXISTING,0,NULL);

	if(disk == INVALID_HANDLE_VALUE) {
		return (FALSE);
	}

	result = DeviceIoControl(disk,IOCTL_DISK_GET_DRIVE_GEOMETRY,
			NULL, 0, pdg, sizeof(*pdg), &junk,
			(LPOVERLAPPED) NULL);

	CloseHandle(disk);
	return(result);

}

void getthedisks() {

	DISK_GEOMETRY pdg;
	BOOL result;
	ULONGLONG size;
	char val[120];
	int disk=0;

	for(disk=0;disk<4;disk++) {
		result = getdisksize(&pdg,disk);
		if(result) {
			size = pdg.Cylinders.QuadPart *
				(ULONG)pdg.TracksPerCylinder *
				(ULONG)pdg.SectorsPerTrack *
				(ULONG)pdg.BytesPerSector;
			size = size / (1024*1024*1024);

			sprintf(val,"Disk %d;%ld Gb\0",disk,size);
			storedata(cname,"HARDWARE/DESCRIPTION/System/DiskSize",val);

		} 
	}

	return;
}
