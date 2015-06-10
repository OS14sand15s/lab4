#include<stdio.h>
#include<unistd.h>
#include<stdlib.h>
#include<sys/types.h>
#include<sys/stat.h>
#include<fcntl.h>
#include<string.h>
#include<ctype.h>
#include "time.h"
#include "filesys.h"
unsigned char *fatbuf;  //You are kidding me!.. sizeof fatbuf:numofcluster*2....
int SECTOR_SIZE=0;
int  CLUSTER_SIZE=0;                     
int FAT_ONE_OFFSET =0;                       
int DATA_OFFSET =0;
int ROOTDIR_OFFSET = 0;  
int NUM_OF_FATS=0;
int FAT_SIZE=0;
int TOTAL_CLUSTER=0;
int FATBUF_SIZE=0;
time_t timer;
struct tm *timeinfo;
char **mynames;
#define RevByte(low,high) ((high)<<8|(low))
#define RevWord(lowest,lower,higher,highest) ((highest)<< 24|(higher)<<16|(lower)<<8|lowest) 
 int CreCreateTime (struct tm *timeinfo)
 {
 	int hour=timeinfo->tm_hour;
 	int min=timeinfo->tm_min;
 	int sec=timeinfo->tm_sec/2;
 	int result=sec|min<<5|hour<<11;
 	return result;
 }
 int CreCreateDate(struct tm *timeinfo){
 	int year=timeinfo->tm_year+1900-1980;
 	int month=timeinfo->tm_mon+1;
 	int day=timeinfo->tm_mday;
 	int result=day|month<<5|year<<9;
 	return result;
 }
void ScanBootSector()
{
	unsigned char buf[512];
	int ret,i;
	if((ret = read(fd,buf,512))<0)
		perror("read boot sector failed");
	for(i = 0; i < 8; i++)
		bdptor.Oem_name[i] = buf[i+0x03];
	bdptor.Oem_name[i] = '\0';
	bdptor.BytesPerSector = RevByte(buf[0x0b],buf[0x0c]);
	bdptor.SectorsPerCluster = buf[0x0d];
	bdptor.ReservedSectors = RevByte(buf[0x0e],buf[0x0f]);
	bdptor.FATs = buf[0x10];
	bdptor.RootDirEntries = RevByte(buf[0x11],buf[0x12]);    
	bdptor.LogicSectors = RevByte(buf[0x13],buf[0x14]);
	bdptor.MediaType = buf[0x15];
	bdptor.SectorsPerFAT = RevByte( buf[0x16],buf[0x17] );
	bdptor.SectorsPerTrack = RevByte(buf[0x18],buf[0x19]);
	bdptor.Heads = RevByte(buf[0x1a],buf[0x1b]);
	bdptor.HiddenSectors = RevByte(buf[0x1c],buf[0x1d]);
	NUM_OF_FATS=bdptor.FATs;
	SECTOR_SIZE=bdptor.BytesPerSector;
	FAT_ONE_OFFSET=SECTOR_SIZE;
	FAT_SIZE=SECTOR_SIZE*bdptor.SectorsPerFAT;
	ROOTDIR_OFFSET = SECTOR_SIZE + NUM_OF_FATS * FAT_SIZE;
	CLUSTER_SIZE=SECTOR_SIZE*bdptor.SectorsPerCluster;
	DATA_OFFSET=ROOTDIR_OFFSET+DIR_ENTRY_SIZE*bdptor.RootDirEntries;
	TOTAL_CLUSTER=bdptor.LogicSectors/bdptor.SectorsPerCluster;
	FATBUF_SIZE=2*TOTAL_CLUSTER;
	mynames=(char **)malloc(sizeof(char*)*TOTAL_CLUSTER);
	fatbuf=(unsigned char *)malloc(FATBUF_SIZE*sizeof(unsigned char));
	printf("Oem_name \t\t%s\n"
		"BytesPerSector \t\t%d\n"
		"SectorsPerCluster \t%d\n"
		"ReservedSector \t\t%d\n"
		"FATs \t\t\t%d\n"
		"RootDirEntries \t\t%d\n"
		"LogicSectors \t\t%d\n"
		"MedioType \t\t%d\n"
		"SectorPerFAT \t\t%d\n"
		"SectorPerTrack \t\t%d\n"
		"Heads \t\t\t%d\n"
		"HiddenSectors \t\t%d\n"
             	"ROOTDIR_OFFSET \t\t%d\n",
		bdptor.Oem_name,
		bdptor.BytesPerSector,
		bdptor.SectorsPerCluster,
		bdptor.ReservedSectors,
		bdptor.FATs,
		bdptor.RootDirEntries,
		bdptor.LogicSectors,
		bdptor.MediaType,
		bdptor.SectorsPerFAT,
		bdptor.SectorsPerTrack,
		bdptor.Heads,
		bdptor.HiddenSectors,
		ROOTDIR_OFFSET);
}
void findDate(unsigned short *year,
			  unsigned short *month,
			  unsigned short *day,
			  unsigned char info[2])
{
	int date;
	date = RevByte(info[0],info[1]);
	*year = ((date & MASK_YEAR)>> 9 )+1980;
	*month = ((date & MASK_MONTH)>> 5);
	*day = (date & MASK_DAY);
}
void findTime(unsigned short *hour,
			  unsigned short *min,
			  unsigned short *sec,
			  unsigned char info[2])
{
	int time;
	time = RevByte(info[0],info[1]);

	*hour = ((time & MASK_HOUR )>>11);
	*min = (time & MASK_MIN)>> 5;
	*sec = (time & MASK_SEC) * 2;
}
void FileNameFormat(unsigned char *name)
{
	unsigned char *p = name;
	int i,j;
	if(name[0]=='.')
	{
		if(name[1]=='.')
			name[2]='\0';
		else
			name[1]='\0';
		return;
	}	
	for(i=0;i<strlen(p)&&p[i]!=' ';i++);
	if(p[8]!=' ')
	{	p[i++]='.';
		for(j=8;j<11;j++)
			p[i++]=p[j];
	}
	p[i]='\0';
}

/*参数：entry，类型：struct Entry*
*返回值：成功，则返回偏移值；失败：返回负值
*功能：从根目录或文件簇中得到文件表项
*/
int GetEntry(struct Entry *pentry)
{
	int ret,i;
	int count = 0;
	unsigned char judge=0xe5;
	unsigned char buf[DIR_ENTRY_SIZE], info[2];
		/*读一个目录表项，即32字节*/
	if( (ret = read(fd,buf,DIR_ENTRY_SIZE))<0)
		perror("read entry failed");
	count += ret;
	if(buf[0]==judge||buf[0]==0x00||buf[11]==0x0f)
	{
		return -1*count;
	}
	else
	{
		/*长文件名，忽略掉*/
		while (buf[11]== 0x0f) 
		{
			if((ret = read(fd,buf,DIR_ENTRY_SIZE))<0)
				perror("read root dir failed");
			count += ret;
		}
		

		/*命名格式化，主义结尾的'\0'*/
		for (i=0 ;i<=10;i++)
			pentry->short_name[i] = buf[i];
		pentry->short_name[i] = '\0';
		FileNameFormat(pentry->short_name); 
		info[0]=buf[22];
		info[1]=buf[23];
		findTime(&(pentry->hour),&(pentry->min),&(pentry->sec),info);  
		info[0]=buf[24];
		info[1]=buf[25];
		findDate(&(pentry->year),&(pentry->month),&(pentry->day),info);
		pentry->FirstCluster = RevByte(buf[26],buf[27]);
		pentry->size = RevWord(buf[28],buf[29],buf[30],buf[31]);
		pentry->readonly = (buf[11] & ATTR_READONLY) ?1:0;
		pentry->hidden = (buf[11] & ATTR_HIDDEN) ?1:0;
		pentry->system = (buf[11] & ATTR_SYSTEM) ?1:0;
		pentry->vlabel = (buf[11] & ATTR_VLABEL) ?1:0;
		pentry->subdir = (buf[11] & ATTR_SUBDIR) ?1:0;
		pentry->archive = (buf[11] & ATTR_ARCHIVE) ?1:0;
		return count;
	}
}

/*
*功能：显示当前目录的内容
*返回值：1，成功；-1，失败
*/
void initial(struct Entry *dir)
{
	int ret,offset,max_offset;
	struct Entry entry;
	offset=dir==NULL?ROOTDIR_OFFSET:DATA_OFFSET + (dir->FirstCluster -2) * CLUSTER_SIZE;
	max_offset=dir==NULL?DATA_OFFSET:offset+CLUSTER_SIZE;
	while(offset<max_offset)
	{
		if((ret= lseek(fd,offset,SEEK_SET))<0)
				perror("lseek ROOTDIR_OFFSET failed");
		ret=GetEntry(&entry);
	 	offset += abs(ret);
	 	if(ret>0)
	 	{
	 		if(entry.subdir&&entry.short_name[0]!='.'){
	 			//puts(entry.short_name);
	 			mynames[entry.FirstCluster]=(char*)malloc(sizeof(char)*12);
	 			strncpy(mynames[entry.FirstCluster],entry.short_name,12);
	 			initial(&entry);
	 		}
	 	}
	 }
	 return;
}
int fd_ls()
{
	int ret, offset,cluster_addr;
	struct Entry entry;
	int max_offset;
	if(curdir==NULL)
		printf("Root_dir\n");
	else
	{
		if(curdir->short_name[0]=='.')
			{
				printf("curdir->FirstCluster:%d\n",curdir->FirstCluster );
				printf("%s_dir\n",mynames[curdir->FirstCluster]);
			}
		else
			printf("%s_dir\n",curdir->short_name );
	}
		
	printf("\tname\tdate\t\t time\t\tcluster\tsize\t\tattr\n");
	offset=curdir==NULL?ROOTDIR_OFFSET:DATA_OFFSET + (curdir->FirstCluster -2) * CLUSTER_SIZE;
	max_offset=curdir==NULL?DATA_OFFSET:offset+CLUSTER_SIZE;
	if((ret= lseek(fd,offset,SEEK_SET))<0)
		perror("lseek ROOTDIR_OFFSET failed");
	while(offset<max_offset)
	{
		//printf("%d\n",entry.short_name[0] );
		ret=GetEntry(&entry);
	 	offset += abs(ret);
		if(ret > 0)
		{
			printf("%12s\t"
			"%d:%d:%d\t"
			"%d:%d:%d   \t"
			"%d\t"
			"%d\t\t"
			"%s\n",
			entry.short_name,
			entry.year,entry.month,entry.day,
			entry.hour,entry.min,entry.sec,
			entry.FirstCluster,
			entry.size,
			(entry.subdir) ? "dir":"file");
		}
	}
	return 0;
} 


/*
*功能：搜索当前目录，查找名为entryname的文件或目录项，如果没找到但会-1，找到了返回目标文件在硬盘中的偏移
*/
int ScanEntry (char *entryname,struct Entry *pentry,int mode,struct Entry *nowdir)
{
	int ret,offset,i;
	int cluster_addr;
	int max_offset;
	char uppername[12];
	for(i=0;i< strlen(entryname);i++)
		uppername[i]= toupper(entryname[i]);
	uppername[i]= '\0';
	offset=nowdir==NULL?ROOTDIR_OFFSET:DATA_OFFSET + (curdir->FirstCluster -2)*CLUSTER_SIZE;
	max_offset=nowdir==NULL?DATA_OFFSET:offset+CLUSTER_SIZE;
	if((ret = lseek(fd,offset,SEEK_SET))<0)
			perror ("lseek ROOTDIR_OFFSET failed");
	while(offset<max_offset)
	{
		ret=GetEntry(pentry);
		offset +=abs(ret);
		if(pentry->subdir == mode &&!strcmp((char*)pentry->short_name,uppername))
			return offset;
	}
	return -1;
}
/*
*参数：dir，类型：char
*返回值：1，成功；-1，失败
*功能：改变目录到父目录或子目录
*/
int fd_ab_cd(char *dir)
{
	char ohmy[20];
	int i=0,j=0;
	struct Entry *tmp=(struct Entry*)malloc(sizeof(struct Entry));
	if(curdir!=NULL)
		memcpy(tmp,curdir,sizeof(struct Entry));
	else
		tmp=NULL;
	curdir=NULL;
	for(i=1;i<strlen(dir);i++)
	{
		if(dir[i]=='/')
		{
			ohmy[j]='\0';
			if(fd_cd(ohmy)<0)
			{
				curdir=tmp;
				return -1;
			}
			j=0;
		}
		else
			ohmy[j++]=dir[i];
	}
}
int fd_cd(char *dir)
{
	struct Entry *pentry;
	int ret,offset;
	if(!strcmp(dir,"."))
	{
		return 1;
	}
	else if(!strcmp(dir,"..") && curdir==NULL)
		return 1;
	else{
		pentry = (struct Entry*)malloc(sizeof(struct Entry));
		ret = ScanEntry(dir,pentry,1,curdir);
		if(ret < 0)
		{
			printf("no such dir\n");
			free(pentry);
			return -1;
		}
		curdir=pentry->FirstCluster?pentry:NULL;
		return 1;
	}
}
/*
*参数：prev，类型：unsigned char
*返回值：下一簇
*在fat表中获得下一簇的位置
*/
unsigned short GetFatCluster(unsigned short prev)
{
	unsigned short next;
	int index;
	index = prev * 2;//*2是因为我们用16bytes来表示一个cluster，这16字节是按照8字节8字节存入fatbuf中
	next = RevByte(fatbuf[index],fatbuf[index+1]);
	return next;
}
/*
*功能：清除fat表中的簇信息
*/
void ClearFatCluster(unsigned short cluster)
{
	int index;
	index = cluster * 2;
	fatbuf[index]=0x00;
	fatbuf[index+1]=0x00;

}
int WriteFat()
{
	int fatid=0;
	for(;fatid<NUM_OF_FATS;fatid++)
	{
		if(lseek(fd,(FAT_ONE_OFFSET+fatid*FAT_SIZE),SEEK_SET)<0)
		{
			perror("lseek failded: ");
			return -1;
		}	
		if(write(fd,fatbuf,FATBUF_SIZE)<0)
		{
			perror("write failed!...");
			return -1;
		}
	}
	return 1;
}

/*
*读fat表的信息，存入fatbuf[]中
*/
int ReadFat()
{
	if(lseek(fd,FAT_ONE_OFFSET,SEEK_SET)<0)
	{
		perror("lseek failed");
		return -1;
	}
	if(read(fd,fatbuf,FATBUF_SIZE)<0)
	{
		perror("read failed");
		return -1;
	}
	return 1;
}


/*
*参数：filename，类型：char
*返回值：1，成功；-1，失败
*功能;删除当前目录下的文件
*/
void pre_rmdir(char *filename)
{
	struct Entry tmpentry;
	int ret;
	unsigned short c=0xe5;
	//tmpentry=(struct Entry *)malloc(sizeof(struct Entry));
	if((ret=ScanEntry(filename,&tmpentry,1,curdir))<0)
	{
		printf("no such dir\n");
	}	
	else{
		//printf("%s\n",tmpentry.short_name);
		fd_rmdir(&tmpentry);
		if(lseek(fd,ret-0x20,SEEK_SET)<0)
			perror("lseek error");
		if(write(fd,&c,1)<0)
			perror("write failed");
	} 

}
void fd_rmdir(struct Entry *pentry)
{
	int seed,next,offset=DATA_OFFSET+ (pentry->FirstCluster -2)*CLUSTER_SIZE,res,max_offset=offset+CLUSTER_SIZE;
	unsigned char c=0xe5;
	struct Entry Item/*=(struct Entry*)malloc(sizeof(struct Entry))*/;
	if(lseek(fd,offset,SEEK_SET)<0)
		perror("lseek fd_rmdir error");
	//*功能：搜索当前目录，查找名为entryname的文件或目录项，如果没找到但会-1，找到了返回目标文件在硬盘中的偏移
	//int ScanEntry (char *entryname,struct Entry *pentry,int mode)
	while(offset<max_offset)
	{
		(res=GetEntry(&Item));
		offset+=abs(res);
		if(res>0)
		{
			if(Item.subdir){
				if(Item.short_name[0]!='.')
				{
					fd_rmdir(&Item);
				}
			}
			else
			{
				seed = Item.FirstCluster;
				while((next = GetFatCluster(seed))!=0xffff)
				{	
					ClearFatCluster(seed);
					seed = next;
				}
				ClearFatCluster( seed );
				if(WriteFat()<0)
					exit(1);
			}
			if(lseek(fd,offset-0x20,SEEK_SET)<0)
				perror("lseek fd_df failed");
			if(write(fd,&c,1)<0)
				perror("write failed");
		}
		if(lseek(fd,offset,SEEK_SET)<0)
			perror("lseek failded.");
	}
	ClearFatCluster(pentry->FirstCluster);
	return;
}
int fd_df(char *filename,struct Entry *nowdir)
{
	struct Entry *pentry;
	int ret;
	unsigned short c;
	unsigned short seed,next;
	pentry = (struct Entry*)malloc(sizeof(struct Entry));
	/*扫描当前目录查找文件*/
	ret = ScanEntry(filename,pentry,0,nowdir);
	if(ret<0)
	{
		printf("no such file:");
		puts(filename);
		free(pentry);
		return -1;
	}
	printf("%s\n",pentry->short_name);
	/*清除fat表项*/
	if(pentry->size){
	seed = pentry->FirstCluster;
	while((next = GetFatCluster(seed))!=0xffff)
	{	
		ClearFatCluster(seed);
		seed = next;

	}
	ClearFatCluster( seed );}
	/*清除目录表项*/
	c=0xe5;//e5表示该目录项可用
	if(lseek(fd,ret-0x20,SEEK_SET)<0)
		perror("lseek fd_df failed");
	if(write(fd,&c,1)<0)
		perror("write failed");  
	free(pentry);
	if(WriteFat()<0)
		exit(1);
	return 1;
}


/*
*参数：filename，类型：char，创建文件的名称
size，    类型：int，文件的大小
*返回值：1，成功；-1，失败
*功能：在当前目录下创建文件
*/
void make_array_c(char*filename,int mode,int nowtime,int nowday,int size,unsigned char *c,unsigned short first_cluster)
{
	int i=0,j;
	if(filename[0]!='.'){
	for(;i<strlen(filename)&&filename[i]!='.';i++)
		c[i]=toupper(filename[i]);
	if(filename[i++]=='.')
	{
		for(j=i;j<8;j++)
			c[j]=' ';
	for(;j<11;j++)
		c[j]=toupper(filename[i++]);//kuo zhan ming..
	}
	else
		for(i;i<11;i++)
			c[i]=' ';
	}
	else
	{
		for(i=0;i<strlen(filename);i++)
			c[i]=filename[i];
		c[i]='\0';

	}
	c[11]=mode?ATTR_SUBDIR:0x01;
	c[14]=nowtime&0x00ff;
	c[15]=(nowtime&0xff00)>>8;
	c[16]=nowday&0x00ff;
	c[17]=(nowday&0xff00)>>8;
	c[22]=c[14];
	c[23]=c[15];
	c[24]=c[16];
	c[25]=c[17];
	c[26] = (first_cluster &  0x00ff);
	c[27] = ((first_cluster & 0xff00)>>8);
	c[28] = (size &  0x000000ff);
	c[29] = ((size & 0x0000ff00)>>8);
	c[30] = ((size& 0x00ff0000)>>16);
	c[31] = ((size& 0xff000000)>>24);
}
void make_dir_point(int nowtime,int nowday,unsigned short cluster,unsigned short cluster_father)
{
	int i=0,offset;
	unsigned char *c;
	offset=(cluster -2)*CLUSTER_SIZE + DATA_OFFSET;
	char itself[2]={'.'},parent[3]={'.','.'};
	c=(unsigned char *)malloc(sizeof(unsigned char)*DIR_ENTRY_SIZE);
	make_array_c(itself,1,nowtime,nowday,0,c,cluster);
	if(lseek(fd,offset,SEEK_SET)<0)
		perror("lseek fd_cf failed");
	if(write(fd,c,DIR_ENTRY_SIZE)<0)
		perror("write . failed");
	make_array_c(parent,1,nowtime,nowday,0,c,cluster_father);
	if(write(fd,c,DIR_ENTRY_SIZE)<0)
		perror("write .. failed..");
	free(c);
}
int fd_mkdir(char *filename)
{
	struct Entry *pentry;
	int i=0,ret,cluster_addr,offset,max_offset,index,clustersize=1,nowtime,nowday,size=0;//size of dir is zero.
	unsigned short cluster,clusterno,cluster_father;
	unsigned char *c;
	unsigned char buf[DIR_ENTRY_SIZE];
	c=(unsigned char *)malloc(sizeof(unsigned char)*DIR_ENTRY_SIZE);
	pentry = (struct Entry*)malloc(sizeof(struct Entry));
	cluster_father=curdir==NULL?0:curdir->FirstCluster;
	ret = ScanEntry(filename,pentry,1,curdir);
	printf("%s\n",filename);
	if (ret<0)
	{
		/*查询fat表，找到空白簇，保存在clusterno中*/
		for(cluster=3;cluster<TOTAL_CLUSTER;cluster++)
		{
			index = cluster *2;
			if(fatbuf[index]==0x00&&fatbuf[index+1]==0x00)
			{
				clusterno = cluster;
				break;
			}
		}
		mynames[clusterno]=(char *)malloc(sizeof(char)*12);
		strcpy(mynames[clusterno],filename);
		index=clusterno*2;
		fatbuf[index] = 0xff;
		fatbuf[index+1] = 0xff;
		offset=curdir==NULL?ROOTDIR_OFFSET:(curdir->FirstCluster -2 )*CLUSTER_SIZE + DATA_OFFSET;
		max_offset=curdir==NULL?DATA_OFFSET:offset+CLUSTER_SIZE;
		if((ret= lseek(fd,offset,SEEK_SET))<0)
			perror("lseek ROOTDIR_OFFSET failed");
		while(offset < max_offset)
		{
		  //读取一个条目
			if((ret = read(fd,buf,DIR_ENTRY_SIZE))<0)
				perror("read entry failed");

			offset += abs(ret);
				//看看条目是否可用（e5）或者是不是表示后面没有更多条目（00）
			if(buf[0]!=0xe5&&buf[0]!=0x00)
			{
				  //buf[11]是attribute，但是感觉下面这个while循环并没有什么卵用。。。
			  while(buf[11] == 0x0f)
				{
					if((ret = read(fd,buf,DIR_ENTRY_SIZE))<0)
						perror("read root dir failed");
					offset +=abs(ret);
				}
			}
			else
			{       
				offset = offset-abs(ret);
				time(&timer);
				timeinfo=localtime(&timer);
				nowtime=CreCreateTime(timeinfo);
				nowday=CreCreateDate(timeinfo);
				make_array_c(filename,1,nowtime,nowday,size,c,clusterno);
				if(lseek(fd,offset,SEEK_SET)<0)
					perror("lseek fd_cf failed");
				if(write(fd,c,DIR_ENTRY_SIZE)<0)
					perror("write failed");
				free(pentry);
				free(c);
				if(WriteFat()<0)
					exit(1);
				make_dir_point(nowtime,nowday,cluster,cluster_father);
				return 1;
			}
		}

	}
	else
	{
		printf("This filename is exist\n");
		free(pentry);
		return -1;
	}
	return 1;
}
int fd_cf(char *filename,int size)
{

	struct Entry *pentry;
	int ret,i=0,cluster_addr,offset,max_offset,index,clustersize,nowtime,nowday;
	unsigned short cluster,*clusterno;
	unsigned char *c;
	unsigned char buf[DIR_ENTRY_SIZE];
	c=(unsigned char*)malloc(sizeof(unsigned char)*DIR_ENTRY_SIZE);
	pentry = (struct Entry*)malloc(sizeof(struct Entry));
	clustersize=!size?0:(size%CLUSTER_SIZE)?(size/CLUSTER_SIZE+1):size/CLUSTER_SIZE;
	clusterno=(unsigned short*)malloc(sizeof(unsigned short)*clustersize);
	ret = ScanEntry(filename,pentry,0,curdir);
	if (ret<0)
	{
		/*查询fat表，找到空白簇，保存在clusterno[]中*/
		if(size){
		for(cluster=3;cluster<TOTAL_CLUSTER;cluster++)		{
			index = cluster *2;
			if(fatbuf[index]==0x00&&fatbuf[index+1]==0x00&&i<clustersize)
				clusterno[i++] = cluster;
			if(i>=clustersize)
				break;

		}
		/*在fat表中写入下一簇信息*/
		for(i=0;i<clustersize-1;i++)
		{
			index = clusterno[i]*2;
			fatbuf[index] = (clusterno[i+1] &  0x00ff);
			fatbuf[index+1] = ((clusterno[i+1] & 0xff00)>>8);

		}
		/*最后一簇写入0xffff*/
		index = clusterno[i]*2;
		fatbuf[index] = 0xff;
		fatbuf[index+1] = 0xff;}
		offset=curdir==NULL?ROOTDIR_OFFSET:(curdir->FirstCluster -2 )*CLUSTER_SIZE + DATA_OFFSET;
		max_offset=curdir==NULL?DATA_OFFSET:offset+CLUSTER_SIZE;
		if((ret= lseek(fd,offset,SEEK_SET))<0)
			perror("lseek ROOTDIR_OFFSET failed");
		while(offset < max_offset)
		{
		  //读取一个条目
			if((ret = read(fd,buf,DIR_ENTRY_SIZE))<0)
				perror("read entry failed");

			offset += abs(ret);
				//看看条目是否可用（e5）或者是不是表示后面没有更多条目（00）
			if(buf[0]!=0xe5&&buf[0]!=0x00)
			{
				  //buf[11]是attribute，但是感觉下面这个while循环并没有什么卵用。。。
			  while(buf[11] == 0x0f)
				{
					if((ret = read(fd,buf,DIR_ENTRY_SIZE))<0)
						perror("read root dir failed");
					offset +=abs(ret);
				}
			}
				/*找出空目录项或已删除的目录项*/ 
			else
			{       
				offset = offset-abs(ret);   
				time(&timer);
				timeinfo=localtime(&timer);
				nowtime=CreCreateTime(timeinfo);
				nowday=CreCreateDate(timeinfo);
				if(size) 
					make_array_c(filename,0,nowtime,nowday,size,c,clusterno[0]);
				else
					make_array_c(filename,0,nowtime,nowday,0,c,0);
				if(lseek(fd,offset,SEEK_SET)<0)
					perror("lseek fd_cf failed");
				if(write(fd,c,DIR_ENTRY_SIZE)<0)
					perror("write failed");
				free(pentry);
				free(c);
				if(WriteFat()<0)
					exit(1);
				return 1;
			}
		}

	}
	else
	{
		printf("This filename is exist\n");
		free(pentry);
		return -1;
	}
	return 1;

}

void do_usage()
{
	printf("please input a command, including followings:"
		"\n\tls\t\t\tlist all files\n\t"
		"cd <dir>\t\tchange direcotry\n\t"
		"cf <filename> <size>\t"
		"create a file\n\tdf <file>\t\t"
		"delete a file\n\t"
		"mkdir <dir>\t\tcreate a direcotry\n\t"
		"rmdir <dir>\t\tremove a direcotry\n\t"
		"exit\t\texit this system\n");
}

int main()
{
	char input[10];
	int size=0,length;
	char name[100];
	if((fd = open(DEVNAME,O_RDWR))<0)
	  perror("open failed");
	ScanBootSector();
	if(ReadFat()<0)
		exit(1);
	do_usage();
	initial(NULL);
	while (1)
	{
		printf(">");
		scanf("%s",input);
		if (strcmp(input, "exit") == 0)
			break;
		else if (strcmp(input, "ls") == 0)
			fd_ls();
		else if(strcmp(input, "cd") == 0)
		{
			scanf("%s",name);
			if(name[0]=='/')
			{
				length=strlen(name);
				if(name[length-1]!='/'){
				name[length]='/';
				name[length+1]='\0';}
				fd_ab_cd(name);
			}
			else
				fd_cd(name);
		}
		else if(strcmp(input, "df") == 0)
		{
			scanf("%s", name);
			fd_df(name,curdir);
		}
		else if(strcmp(input, "cf") == 0)
		{
			scanf("%s", name);
			scanf("%s", input);
			size = atoi(input);
			fd_cf(name,size);
		}
		else if(!strcmp(input, "mkdir"))
		{
			scanf("%s",name);
			fd_mkdir(name);
		}
		else if(!strcmp(input,"rmdir"))
		{
			scanf("%s",name);
			pre_rmdir(name);
		}
		else
			do_usage();
	}	
	free(fatbuf);
	return 0;
}
