#include <studio.h>
#include <math.h>

int main()
{
     float a, b, c, s, area;
     printf("enter sides of a triangle \n");

     scanf("%f%f%f", &a,&b,&c);
     s=(a+b+c)/2;   //semiperimeter
     area= sqrt(s*(s-a)*(s-b)*(s-c));
     printf("area of a triangle= %.2f", area);

     return 0
}
