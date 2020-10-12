#include <stdio.h>

int main()
{
    int a=10,c;
    c=a;    //c=10
    printf("c= %d \n",c);
    c+=a;   //c=20
    printf("c= %d \n",c);
    c-=a;   //c=10
    printf("c= %d \n",c);
    c*=a;   //c=100
    printf("c= %d \n",c);
    c/=a;   //c=10
    printf("c= %d \n",c);
    c%=a;   //c=0
    printf("c= %d \n",c);
    return 0;
}
