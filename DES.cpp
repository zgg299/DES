#include<openssl/des.h>
#include<openssl/evp.h>
#include<openssl/err.h>
#include<iostream>
#include<stdlib.h>
#include<string>
#include<fstream>
#include<sstream>
#include<stdio.h>
#include<string.h>
using namespace std;

typedef unsigned char DES_cblock[8];

DES_cblock key;
string des_key,str;
DES_key_schedule schedule; 
DES_cblock ivec; 

//从文件中读入到字符数组中
void readFileIntoString(char* filename,string &string){
    ifstream ifile(filename);
    ostringstream buf;
    char ch;
    while(buf&&ifile.get(ch)){
        buf.put(ch);
    }
        string=buf.str();
    
}


void writefile(char* p,string filename){
  FILE *fp=fopen(filename.c_str(),"w+");
  if(fp==NULL){
    printf("Failed to open the file!");
    exit(-1);
  }
  if(fputs(p,fp)==EOF)printf("Failed to open the file!");
  fclose(fp);
}
void stringToDEScblock(string str,DES_cblock it){
    for(int i=0;i<8;++i){
            it[i]=str[i];
    }
        
}

void DEScblockTostring(DES_cblock it,string str){
    for(int i=0;i<8;++i){
        str[i]=it[i];
    }
}


int hextoDec(char ch) {
	int temp;
	if (ch >= '0'&&ch <= '9') {
		temp = ch - '0';
	}
	else if (ch >= 'A'&&ch <= 'F') {
		temp = ch - 'A' + 10;
	}
	else{
      cout << " wrong number\n" << endl;
  }
		
	return temp;
}

//十六进制转换为字符串
string HexToString(string stringtemp) {
	string result = "";
	for (int i = 0; i < stringtemp.length(); i += 2) {
		char temp[2];
		temp[0] = stringtemp[i];
		temp[1] = stringtemp[i + 1];
		int temp1 = hextoDec(temp[1]);
		int temp2 = hextoDec(temp[0]);
		int temp3 = temp2 * 16 + temp1;
		char ch = temp3;
		result.append(1,ch);

	}
	return result;
}

void setkey(){
    readFileIntoString("des_key.txt",str);  
    des_key=HexToString(str);
    stringToDEScblock(des_key,key); 
    DES_set_key_unchecked(&key, &schedule); 

}

//ECB加密
void encrypt_ECB(){
  readFileIntoString("des_messages.txt",str);
    int times=0;
    if(str.length()%16==0){
        times=str.length()/16;
    }
    else
    {
        times=str.length()/16+1;
    }

    
   //加密用的数据块
    string blocks[times];
    for(int i=0;i<times;++i){
      blocks[i]=str.substr(0+i*16,16);
    }
    
    //加密
    string input_message,output_message,temp;
    char tempresult[1000];
    DES_cblock input,output; 
    for(int i=0;i<times;++i){
    string str3=blocks[i];
    input_message=HexToString(str3);
    stringToDEScblock(input_message,input);   
    DES_ecb_encrypt(&input, &output, &schedule, DES_ENCRYPT); 
    DEScblockTostring(output,temp); 
    for(int i=0;i<sizeof(input);++i){
      sprintf(tempresult,"%02X",output[i]);
      string temp=tempresult;
      output_message.append(temp);
    }
    
    
    }
    cout<<"这是加密，密文是:"<<endl; 
    cout<<output_message<<endl;
    char ch[1000];
    int i;
    for(i=0;i<output_message.length();++i){
           ch[i]=output_message[i];
    }
    ch[i]='\0';
    writefile(ch,"des_secret_ECB.txt");

}




//ECB解密
void decrypt_ECB()
{      
    readFileIntoString("des_secret_ECB.txt",str);
    int times=0;
    if(str.length()%16==0){
        times=str.length()/16;
    }
    else
    {
        times=str.length()/16+1;
    }

    //解密用的数据块
    string deblocks[times];
    for(int i=0;i<times;++i){
      deblocks[i]=str.substr(0+i*16,16);
    }
    //解密  循环的次数相同
    string input_message,output_message,temp;
    char tempresult[1000];
    DES_cblock input,output;
     for(int i=0;i<times;++i){
       string str4=deblocks[i];
       output_message=HexToString(str4);
       stringToDEScblock(output_message,output);   
       DES_ecb_encrypt(&output, &input, &schedule, DES_DECRYPT); 
       DEScblockTostring(input,temp); 
       for(int i=0;i<sizeof(input);++i){
       sprintf(tempresult,"%02X",input[i]);
       string temp=tempresult;
       input_message.append(temp);
    }
    
    
    }
    cout<<"这是解密，明文是:"<<endl; 
    cout<<input_message<<endl;
    char ch[1000];
    int i;
    for(i=0;i<input_message.length();++i){
           ch[i]=input_message[i];
    }
    ch[i]='\0';
    writefile(ch,"des_decrypted.txt");
}   

//IV设置值  我不晓得为什么把代码写成函数就可正常运行，写在加密函数里面就会出问题
void setiv(){
      string str2;
      readFileIntoString("des_iv.txt",str2);
      string str1=HexToString(str2);
       for(int i=0;i<8;++i){
        ivec[i]=str1[i];
      }
}
//不要问我为什么写这个函数，因为我放在加密函数中不对，但是单独写出来就对了
void writeCBC(size_t len,unsigned char* output){
      char tempresult[1000];
      string output_message="";
      for(int i=0;i<len;++i){
         sprintf(tempresult,"%02X",output[i]);
         string temp=tempresult;
         output_message.append(temp);
      }
      char ch[1000];
      int i;
     for(i=0;i<output_message.length();++i){
           ch[i]=output_message[i];
     }
     ch[i]='\0';
      writefile(ch,"des_secret_CBC.txt");
}

void writeCBC2(size_t len,unsigned char* output){
         char tempresult[1000];
      string output_message="";
      for(int i=0;i<len;++i){
         sprintf(tempresult,"%02X",output[i]);
         string temp=tempresult;
         output_message.append(temp);
      }
      char ch[1000];
      int i;
     for(i=0;i<output_message.length();++i){
           ch[i]=output_message[i];
     }
     ch[i]='\0';
      writefile(ch,"des_decrypted.txt");
}
//CBC加密 
void encrypt_CBC()     
{  


      //需要加密的字符串  
      readFileIntoString("des_messages.txt",str);
      string strtemp=HexToString(str);
      unsigned char input[]={NULL};
      int i;
      for(i=0;i<strtemp.length();++i){
        input[i]=strtemp[i];
      }
      input[i]='\0';
  
  
      int size=0;
      for(i=0;input[i]!='\0';++i){
        size+=sizeof(input[i]);
      }
      size_t len = (size+7)/8 * 8;  
     
      unsigned char *output = NULL;
      output=(unsigned char*)malloc(len+1);
      if(output==NULL)
         exit(0);
      memset(output,0,sizeof(output));  
    
    //迷之调用 
     setiv(); 


    //加密  
      DES_ncbc_encrypt(input, output, size, &schedule, &ivec, DES_ENCRYPT);  
  
      //输出加密以后的内容  
      cout<<"这是加密结果"<<endl;
      for (int i = 0; i < len; ++i)  
         printf("%02x", output[i]);  
      printf("\n");  
      
      writeCBC(len,output);
      memset((char*)&ivec, 0, sizeof(ivec));  
      free(output);
}  

//CBC解密
void decrypt_CBC(){
      
      //需要解密的字符串  
      readFileIntoString("des_secret_CBC.txt",str);
      string strtemp=HexToString(str);
      unsigned char output[]={NULL};
      int i;
      for(i=0;i<strtemp.length();++i){
        output[i]=strtemp[i];
      }
      output[i]='\0';
  
  
      int size=0;
      for(i=0;output[i]!='\0';++i){
        size+=sizeof(output[i]);
      }
      size_t len = (size+7)/8 * 8;  
     
      unsigned char *input = NULL;
      input=(unsigned char*)malloc(len+1);
      if(input==NULL)
         exit(0);
      memset(input,0,sizeof(input));  
    
    //迷之调用 
     setiv(); 


    //解密 
      DES_ncbc_encrypt(output, input, len, &schedule, &ivec, DES_DECRYPT);  

      
      writeCBC2(len,input);
      memset((char*)&ivec, 0, sizeof(ivec)); 
        
      cout<<"这是解密结果"<<endl;
      for (int i = 0; i < len; ++i)  
         printf("%02x", input[i]);   
      cout<<endl;
      free(input);  

}

void show(){
   cout<<"1. ECB encrypt"<<endl;
   cout<<"2. ECB decrypt"<<endl;
   cout<<"3. CBC encrypt"<<endl;
   cout<<"4. CBC decrypt"<<endl;
   cout<<"5. quit"<<endl;
   cout<<"chose your choice(enter the number)"<<endl;
   char choice=getchar();
   while(choice!='5'){
   switch (choice)
   {
    case '1':
       encrypt_ECB();break;
    case '2':
       decrypt_ECB();break;
    case '3':
       encrypt_CBC();break;
    case '4':
       decrypt_CBC();break;
   default:
       break;
   }
   cout<<"chose your choice(enter the number)"<<endl;
   getchar();
   choice=getchar();
 } 
}

int main(){
  setkey();
  show();
	return 0;
}
