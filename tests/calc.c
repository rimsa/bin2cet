#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

int add(int a, int b) {
  return a + b;
}

int subtract(int a, int b) {
  return a - b;
}

int multiply(int a, int b) {
  return a * b;
}

int divide(int a, int b) {
  assert(b != 0);
  return a / b;
}

int main(int argc, char* argv[]) {
  int (*op)(int, int);
  int x, y, res;

  if (argc != 4) {
    printf("Usage: %s [Num] [+|-|*|/] [Int]\n", argv[0]);
    return 1;
  }

  x = atoi(argv[1]);
  y = atoi(argv[3]);
  if (!strcmp(argv[2],"+"))
    op = &add;
  else if (!strcmp(argv[2],"-"))
    op = &subtract;
  else if (!strcmp(argv[2],"*"))
    op = &multiply;
  else if (!strcmp(argv[2],"/"))
    op = &divide;
  else {
    fprintf(stderr, "Invalid operation: %s\n", argv[2]);
    return 1;
  }

  res = op(x, y);
  printf("%d %s %d = %d\n", x, argv[2], y, res);
  return 0;
}
