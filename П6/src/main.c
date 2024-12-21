if (inj_cond)
    inj_cond->fix_fields(thd, 0);

if (inj_cond && inject_cond_into_where(inj_cond->copy_andor_structure(thd))) {
    return true;
}
