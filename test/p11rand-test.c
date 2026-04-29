/* Tiny CLI driver: dlopen() the module, list slots, ask the first slot's
 * token for 32 random bytes, dump them as hex.
 *
 * Usage: p11rand-test ./libp11rand.so [byte_count]
 */

#include "../include/pkcs11.h"

#include <dlfcn.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void die(const char *what, CK_RV rv)
{
    fprintf(stderr, "%s failed: 0x%lx\n", what, (unsigned long)rv);
    exit(2);
}

static void show_field(const char *label, const unsigned char *p, size_t n)
{
    /* PKCS#11 strings are space-padded; trim trailing spaces. */
    while (n && p[n - 1] == ' ') n--;
    printf("  %-12s %.*s\n", label, (int)n, p);
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr, "usage: %s <module.so> [nbytes]\n", argv[0]);
        return 1;
    }
    size_t n = (argc >= 3) ? strtoul(argv[2], NULL, 0) : 32;

    void *h = dlopen(argv[1], RTLD_NOW);
    if (!h) { fprintf(stderr, "dlopen: %s\n", dlerror()); return 2; }

    CK_RV (*GetFunctionList)(CK_FUNCTION_LIST_PTR_PTR);
    *(void **)&GetFunctionList = dlsym(h, "C_GetFunctionList");
    if (!GetFunctionList) { fprintf(stderr, "dlsym C_GetFunctionList: %s\n", dlerror()); return 2; }

    CK_FUNCTION_LIST_PTR f = NULL;
    CK_RV rv = GetFunctionList(&f);
    if (rv != CKR_OK) die("C_GetFunctionList", rv);

    rv = f->C_Initialize(NULL);
    if (rv != CKR_OK) die("C_Initialize", rv);

    /* Enumerate every reader (tokenPresent=FALSE) so we can show empty
     * slots; then enumerate again with tokenPresent=TRUE to pick a slot
     * whose card actually answers GET CHALLENGE. */
    CK_ULONG nall = 0;
    rv = f->C_GetSlotList(CK_FALSE, NULL, &nall);
    if (rv != CKR_OK) die("C_GetSlotList(size, all)", rv);
    CK_SLOT_ID *all = nall ? calloc(nall, sizeof(*all)) : NULL;
    if (nall) {
        rv = f->C_GetSlotList(CK_FALSE, all, &nall);
        if (rv != CKR_OK) die("C_GetSlotList(all)", rv);
    }

    printf("readers visible: %lu\n", (unsigned long)nall);
    for (CK_ULONG i = 0; i < nall; i++) {
        CK_SLOT_INFO si;
        if (f->C_GetSlotInfo(all[i], &si) != CKR_OK) continue;
        const char *mark = (si.flags & CKF_TOKEN_PRESENT) ? "[token]" : "[empty]";
        printf("[%lu] %s flags=0x%lx\n", (unsigned long)all[i], mark,
               (unsigned long)si.flags);
        show_field("reader", si.slotDescription, sizeof(si.slotDescription));
    }

    CK_ULONG nuse = 0;
    rv = f->C_GetSlotList(CK_TRUE, NULL, &nuse);
    if (rv != CKR_OK) die("C_GetSlotList(size, present)", rv);
    if (nuse == 0) {
        fprintf(stderr, "no usable token in any reader\n");
        free(all);
        f->C_Finalize(NULL);
        return 3;
    }
    CK_SLOT_ID *use = calloc(nuse, sizeof(*use));
    if (!use) return 2;
    rv = f->C_GetSlotList(CK_TRUE, use, &nuse);
    if (rv != CKR_OK) die("C_GetSlotList(present)", rv);

    CK_SLOT_ID picked = use[0];
    printf("using slot %lu (first with a usable token, of %lu)\n",
           (unsigned long)picked, (unsigned long)nuse);

    CK_SESSION_HANDLE sess = 0;
    rv = f->C_OpenSession(picked, CKF_SERIAL_SESSION, NULL, NULL, &sess);
    if (rv != CKR_OK) die("C_OpenSession", rv);

    CK_TOKEN_INFO ti;
    if (f->C_GetTokenInfo(picked, &ti) == CKR_OK) {
        puts("token:");
        show_field("label", ti.label,          sizeof(ti.label));
        show_field("model", ti.model,          sizeof(ti.model));
        show_field("mfr",   ti.manufacturerID, sizeof(ti.manufacturerID));
        printf("  flags        0x%lx\n", (unsigned long)ti.flags);
    }

    uint8_t *buf = calloc(1, n);
    if (!buf) return 2;
    rv = f->C_GenerateRandom(sess, buf, (CK_ULONG)n);
    if (rv != CKR_OK) die("C_GenerateRandom", rv);

    printf("random[%zu]: ", n);
    for (size_t i = 0; i < n; i++) printf("%02x", buf[i]);
    putchar('\n');

    free(buf);
    free(use);
    free(all);
    f->C_CloseSession(sess);
    f->C_Finalize(NULL);
    dlclose(h);
    return 0;
}
