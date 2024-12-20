if (thd->locked_tables_list.locked_tables())
{
    if (thd->locked_tables_list.reopen_tables(thd, false))
        goto end;
    table_list->table=pos_in_locked_tables->table;
}
