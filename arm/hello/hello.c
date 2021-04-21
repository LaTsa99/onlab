#include <stdio.h>
#include <stdlib.h>

int main(){
	int array1[20] = {3, 5, 6, 7, 7, 12, 40, 22, 35, 36,
					1, 41, 127, 29, 69, 53, 25, 77, 99, 86};
	int array2[12] = {9, 14, 25, 124, 55, 51, 15, 111, 95, 33, 43, 53};

	printf("Array 1 before sort:\n");
	for(int i = 0; i < 20; i++){
		printf("%d ", array1[i]);
	}
	puts("");

	bubble(array1, 20);

	printf("Array 1 after sort:\n");
	for(int i = 0; i < 20; i++){
		printf("%d ", array1[i]);
	}
	puts("");

	printf("Array 2 before sort:\n");
	for(int i = 0; i < 12; i++){
		printf("%d ", array2[i]);
	}
	puts("");

	bubble(array2, 12);

	printf("Array 2 after sort:\n");
	for(int i = 0; i < 12; i++){
		printf("%d ", array2[i]);
	}
	puts("");

	int *ret = NULL;
	ret = merge(array1, 20, array2, 12);
	printf("Merged array:\n");
	for(int i = 0; i < 32; i++){
		printf("%d ", ret[i]);
	}
	free(ret);
	return 0;
}
