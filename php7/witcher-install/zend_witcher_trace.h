#ifndef ZEND_WEBCAM_TRACE_H
#define ZEND_WEBCAM_TRACE_H

#include "../Zend/zend_compile.h"
#include "zend.h"

extern void vld_external_trace(const char *op, const zend_op *opline, zend_execute_data *execute_data);
extern void witcher_cgi_trace_finish(void);
extern void witcher_cgi_trace_init(char * ch_shm_id);
extern void vld_start_trace();

#define VM_TRACE_START() vld_start_trace();
#define VM_TRACE(op) vld_external_trace(#op, opline, execute_data);
#define VM_TRACE_END() witcher_cgi_trace_finish();
//+ disable smart branch
#define VM_SMART_OPCODES 0

#endif /* ZEND_WEBCAM_TRACE_H */