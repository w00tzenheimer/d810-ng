# TODO


## Issue

```
180136870: INTERR 51810
Exception in SwigDirector_optblock_t::func (SWIG director method error. Error detected when calling 'optblock_t.func')
Traceback (most recent call last):
  File "C:\Users/reverser/AppData/Roaming/Hex-Rays/IDA Pro/plugins\d810\hexrays\hexrays_hooks.py", line 263, in func
    nb_patch = self.optimize(blk)
  File "C:\Users/reverser/AppData/Roaming/Hex-Rays/IDA Pro/plugins\d810\hexrays\hexrays_hooks.py", line 302, in optimize
    nb_patch = cfg_rule.optimize(blk)
  File "C:\Users/reverser/AppData/Roaming/Hex-Rays/IDA Pro/plugins\d810\optimizers\microcode\flow\flattening\generic.py", line 1168, in optimize
    self.last_pass_nb_patch_done = self.remove_flattening()
                                   ~~~~~~~~~~~~~~~~~~~~~~^^
  File "C:\Users/reverser/AppData/Roaming/Hex-Rays/IDA Pro/plugins\d810\optimizers\microcode\flow\flattening\generic.py", line 1044, in remove_flattening
    self.non_significant_changes += self.ensure_all_dispatcher_fathers_are_direct()
                                    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~^^
  File "C:\Users/reverser/AppData/Roaming/Hex-Rays/IDA Pro/plugins\d810\optimizers\microcode\flow\flattening\generic.py", line 464, in ensure_all_dispatcher_fathers_are_direct
    nb_change += self.ensure_dispatcher_fathers_are_direct(dispatcher_info)
                 ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~^^^^^^^^^^^^^^^^^
  File "C:\Users/reverser/AppData/Roaming/Hex-Rays/IDA Pro/plugins\d810\optimizers\microcode\flow\flattening\generic.py", line 482, in ensure_dispatcher_fathers_are_direct
    nb_change += ensure_child_has_an_unconditional_father(
                 ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~^
        dispatcher_father, dispatcher_info.entry_block.blk
        ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
    )
    ^
  File "C:\Users/reverser/AppData/Roaming/Hex-Rays/IDA Pro/plugins\d810\hexrays\cfg_utils.py", line 552, in ensure_child_has_an_unconditional_father
    new_father_block = insert_nop_blk(mba.get_mblock(mba.qty - 2))
  File "C:\Users/reverser/AppData/Roaming/Hex-Rays/IDA Pro/plugins\d810\hexrays\cfg_utils.py", line 368, in insert_nop_blk
    nop_block.insert_into_block(cur_inst, nop_block.head)
    ~~~~~~~~~~~~~~~~~~~~~~~~~~~^^^^^^^^^^^^^^^^^^^^^^^^^^
  File "C:\IDA\9\python\ida_hexrays.py", line 8363, in insert_into_block
    val = _ida_hexrays.mblock_t_insert_into_block(self, nm, om)
RuntimeError: INTERR: 51810
180136870: INTERR 51810
Exception in SwigDirector_optblock_t::func (SWIG director method error. Error detected when calling 'optblock_t.func')
Traceback (most recent call last):
  File "C:\Users/reverser/AppData/Roaming/Hex-Rays/IDA Pro/plugins\d810\hexrays\hexrays_hooks.py", line 263, in func
    nb_patch = self.optimize(blk)
  File "C:\Users/reverser/AppData/Roaming/Hex-Rays/IDA Pro/plugins\d810\hexrays\hexrays_hooks.py", line 302, in optimize
    nb_patch = cfg_rule.optimize(blk)
  File "C:\Users/reverser/AppData/Roaming/Hex-Rays/IDA Pro/plugins\d810\optimizers\microcode\flow\flattening\generic.py", line 1168, in optimize
    self.last_pass_nb_patch_done = self.remove_flattening()
                                   ~~~~~~~~~~~~~~~~~~~~~~^^
  File "C:\Users/reverser/AppData/Roaming/Hex-Rays/IDA Pro/plugins\d810\optimizers\microcode\flow\flattening\generic.py", line 1044, in remove_flattening
    self.non_significant_changes += self.ensure_all_dispatcher_fathers_are_direct()
                                    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~^^
  File "C:\Users/reverser/AppData/Roaming/Hex-Rays/IDA Pro/plugins\d810\optimizers\microcode\flow\flattening\generic.py", line 464, in ensure_all_dispatcher_fathers_are_direct
    nb_change += self.ensure_dispatcher_fathers_are_direct(dispatcher_info)
                 ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~^^^^^^^^^^^^^^^^^
  File "C:\Users/reverser/AppData/Roaming/Hex-Rays/IDA Pro/plugins\d810\optimizers\microcode\flow\flattening\generic.py", line 482, in ensure_dispatcher_fathers_are_direct
    nb_change += ensure_child_has_an_unconditional_father(
                 ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~^
        dispatcher_father, dispatcher_info.entry_block.blk
        ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
    )
    ^
  File "C:\Users/reverser/AppData/Roaming/Hex-Rays/IDA Pro/plugins\d810\hexrays\cfg_utils.py", line 552, in ensure_child_has_an_unconditional_father
    new_father_block = insert_nop_blk(mba.get_mblock(mba.qty - 2))
  File "C:\Users/reverser/AppData/Roaming/Hex-Rays/IDA Pro/plugins\d810\hexrays\cfg_utils.py", line 368, in insert_nop_blk
    nop_block.insert_into_block(cur_inst, nop_block.head)
    ~~~~~~~~~~~~~~~~~~~~~~~~~~~^^^^^^^^^^^^^^^^^^^^^^^^^^
  File "C:\IDA\9\python\ida_hexrays.py", line 8363, in insert_into_block
    val = _ida_hexrays.mblock_t_insert_into_block(self, nm, om)
RuntimeError: INTERR: 51810
180136870: INTERR 51810
Exception in SwigDirector_optblock_t::func (SWIG director method error. Error detected when calling 'optblock_t.func')
Traceback (most recent call last):
  File "C:\Users/reverser/AppData/Roaming/Hex-Rays/IDA Pro/plugins\d810\hexrays\hexrays_hooks.py", line 263, in func
    nb_patch = self.optimize(blk)
  File "C:\Users/reverser/AppData/Roaming/Hex-Rays/IDA Pro/plugins\d810\hexrays\hexrays_hooks.py", line 302, in optimize
    nb_patch = cfg_rule.optimize(blk)
  File "C:\Users/reverser/AppData/Roaming/Hex-Rays/IDA Pro/plugins\d810\optimizers\microcode\flow\flattening\generic.py", line 1168, in optimize
    self.last_pass_nb_patch_done = self.remove_flattening()
                                   ~~~~~~~~~~~~~~~~~~~~~~^^
  File "C:\Users/reverser/AppData/Roaming/Hex-Rays/IDA Pro/plugins\d810\optimizers\microcode\flow\flattening\generic.py", line 1044, in remove_flattening
    self.non_significant_changes += self.ensure_all_dispatcher_fathers_are_direct()
                                    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~^^
  File "C:\Users/reverser/AppData/Roaming/Hex-Rays/IDA Pro/plugins\d810\optimizers\microcode\flow\flattening\generic.py", line 464, in ensure_all_dispatcher_fathers_are_direct
    nb_change += self.ensure_dispatcher_fathers_are_direct(dispatcher_info)
                 ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~^^^^^^^^^^^^^^^^^
  File "C:\Users/reverser/AppData/Roaming/Hex-Rays/IDA Pro/plugins\d810\optimizers\microcode\flow\flattening\generic.py", line 482, in ensure_dispatcher_fathers_are_direct
    nb_change += ensure_child_has_an_unconditional_father(
                 ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~^
        dispatcher_father, dispatcher_info.entry_block.blk
        ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
    )
    ^
  File "C:\Users/reverser/AppData/Roaming/Hex-Rays/IDA Pro/plugins\d810\hexrays\cfg_utils.py", line 552, in ensure_child_has_an_unconditional_father
    new_father_block = insert_nop_blk(mba.get_mblock(mba.qty - 2))
  File "C:\Users/reverser/AppData/Roaming/Hex-Rays/IDA Pro/plugins\d810\hexrays\cfg_utils.py", line 368, in insert_nop_blk
    nop_block.insert_into_block(cur_inst, nop_block.head)
    ~~~~~~~~~~~~~~~~~~~~~~~~~~~^^^^^^^^^^^^^^^^^^^^^^^^^^
  File "C:\IDA\9\python\ida_hexrays.py", line 8363, in insert_into_block
    val = _ida_hexrays.mblock_t_insert_into_block(self, nm, om)
RuntimeError: INTERR: 51810

  _     ._   __/__   _ _  _  _ _/_   Recorded: 13:16:22  Samples:  27153
 /_//_/// /_\ / //_// / //_'/ //     Duration: 2869.256  CPU time: 128.188
/   _/                      v5.0.2

Profile at C:\Users/reverser/AppData/Roaming/Hex-Rays/IDA Pro/plugins\d810\manager.py:44

2869.243 MainThread  <thread>:43360
├─ 2361.996 [self]  <thread>
└─ 475.495 D810ConfigForm_t._edit_config  d810\ui\ida_ui.py:637
   └─ 475.495 D810ConfigForm_t._internal_config_creation  d810\ui\ida_ui.py:648
   ```
   
   
## Issue


Wrong!

```
2025-07-21 14:39:17,550 - D810.optimizer - DEBUG - [fold_const] Checking ins @ 0x1800D36AF (opcode=mov) l=call $sub_18000ECE0<fast:"int n0x3E" #0x3E.4,"__int64 a2" %arg_20.8,"int n0x55" #0x55.4,"int n0x57" #0x57.4,"unsigned int n8" r9d.4>.8 r=
call $sub_18000ECE0<fast:"int n0x3E" #0x3E.4,"__int64 a2" %arg_20.8,"int n0x55" #0x55.4,"int n0x57" #0x57.4,"unsigned int n8" r9d.4>.8 d=call $sub_18000ECE0<fast:"int n0x3E" #0x3E.4,"__int64 a2" %arg_20.8,"int n0x55" #0x55.4,"int n0x57" #0x57.
4,"unsigned int n8" r9d.4>.8
2025-07-21 14:39:17,550 - D810.optimizer - DEBUG - [fold_const] AST for ins: AstProxy(AstConstant(0x3e))
2025-07-21 14:39:17,550 - D810.optimizer - DEBUG - [fold_const] _eval_subtree result: 62
2025-07-21 14:39:17,550 - D810.optimizer - INFO - [fold_const] Collapsed ins at 0x1800D36AF to constant 0x3E (opcode=mov)
2025-07-21 14:39:17,551 - D810.optimizer - INFO - Rule FoldPureConstantRule matched in maturity MMAT_GLBOPT1:
2025-07-21 14:39:17,551 - D810.optimizer - INFO -   orig:  mov      call $sub_18000ECE0<fast:"int n0x3E"  #0x3E.4 ,"__int64 a2" %arg_20.8,"int n0x55"  #0x55.4 ,"int n0x57"  #0x57.4 ,"unsigned int n8" r9d.4>.8 , rax.8
2025-07-21 14:39:17,551 - D810.optimizer - INFO -   new :  ldc      #0x3E.8 , rax.8
2025-07-21 14:39:17,551 - D810.optimizer - DEBUG - [fold_const] New MBA detected! 1689379888640
2025-07-21 14:39:17,551 - D810.optimizer - DEBUG - [fold_const] Skipping mov with constant source (would create infinite loop)
2025-07-21 14:39:17,551 - D810.optimizer - DEBUG - [fold_const] blk is None, ins @ 0x1800D36AF with opcode: mov
2025-07-21 14:39:17,551 - D810.optimizer - DEBUG - [fold_const] Skipping mov with constant source (would create infinite loop)
2025-07-21 14:39:17,551 - D810.unflat - INFO - Unflattening at maturity 5 pass 0
2025-07-21 14:39:17,551 - D810.unflat - INFO - No dispatcher found at maturity 5
2025-07-21 14:39:17,551 - D810 - INFO - Starting decompilation of function at 0x1800d3690
2025-07-21 14:39:17,557 - D810.unflat - INFO - Unflattening at maturity 4 pass 0
2025-07-21 14:39:17,557 - D810.unflat - INFO - No dispatcher found at maturity 4
2025-07-21 14:39:17,557 - D810.optimizer - DEBUG - [fold_const] New MBA detected! 1689379888720
2025-07-21 14:39:17,557 - D810.optimizer - DEBUG - [fold_const] Checking ins @ 0x1800D36AF (opcode=mov) l=call $sub_18000ECE0<fast:"int n0x3E" #0x3E.4,"__int64 a2" %arg_20.8,"int n0x55" #0x55.4,"int n0x57" #0x57.4,"unsigned int n8" r9d.4>.8 r=
call $sub_18000ECE0<fast:"int n0x3E" #0x3E.4,"__int64 a2" %arg_20.8,"int n0x55" #0x55.4,"int n0x57" #0x57.4,"unsigned int n8" r9d.4>.8 d=call $sub_18000ECE0<fast:"int n0x3E" #0x3E.4,"__int64 a2" %arg_20.8,"int n0x55" #0x55.4,"int n0x57" #0x57.
4,"unsigned int n8" r9d.4>.8
2025-07-21 14:39:17,557 - D810.optimizer - DEBUG - [fold_const] AST for ins: AstProxy(AstConstant(0x3e))
2025-07-21 14:39:17,557 - D810.optimizer - DEBUG - [fold_const] _eval_subtree result: 62
2025-07-21 14:39:17,557 - D810.optimizer - INFO - [fold_const] Collapsed ins at 0x1800D36AF to constant 0x3E (opcode=mov)
2025-07-21 14:39:17,557 - D810.optimizer - INFO - Rule FoldPureConstantRule matched in maturity MMAT_GLBOPT1:
2025-07-21 14:39:17,558 - D810.optimizer - INFO -   orig:  mov      call $sub_18000ECE0<fast:"int n0x3E"  #0x3E.4 ,"__int64 a2" %arg_20.8,"int n0x55"  #0x55.4 ,"int n0x57"  #0x57.4 ,"unsigned int n8" r9d.4>.8 , rax.8
2025-07-21 14:39:17,558 - D810.optimizer - INFO -   new :  ldc      #0x3E.8 , rax.8
2025-07-21 14:39:17,558 - D810.optimizer - DEBUG - [fold_const] New MBA detected! 1689379889200
2025-07-21 14:39:17,558 - D810.optimizer - DEBUG - [fold_const] Skipping mov with constant source (would create infinite loop)
2025-07-21 14:39:17,558 - D810.optimizer - DEBUG - [fold_const] blk is None, ins @ 0x1800D36AF with opcode: mov
2025-07-21 14:39:17,558 - D810.optimizer - DEBUG - [fold_const] Skipping mov with constant source (would create infinite loop)
2025-07-21 14:39:17,558 - D810.unflat - INFO - Unflattening at maturity 5 pass 0
2025-07-21 14:39:17,558 - D810.unflat - INFO - No dispatcher found at maturity 5
2025-07-21 14:39:20,923 - D810 - INFO - glbopt finished for function at 0x1800d3690
2025-07-21 14:39:20,923 - D810 - INFO - Instruction optimizer 'PeepholeOptimizer' has been used 1 times
2025-07-21 14:39:20,923 - D810 - INFO - Instruction Rule 'FoldPureConstantRule' has been used 1 times
2025-07-21 14:39:20,923 - D810 - INFO - MOP_CONSTANT_CACHE stats: Stats(seq=0, size=0, weight=0.0, hits=0, misses=0, max_size_ever=0, max_weight_ever=0.0)
2025-07-21 14:39:20,923 - D810 - INFO - MOP_TO_AST_CACHE stats: Stats(seq=58829, size=0, weight=0.0, hits=0, misses=0, max_size_ever=2, max_weight_ever=2.0)
2025-07-21 14:39:20,957 - D810 - INFO - Starting decompilation of function at 0x1800d3690
2025-07-21 14:39:20,965 - D810.unflat - INFO - Unflattening at maturity 4 pass 0
2025-07-21 14:39:20,966 - D810.unflat - INFO - No dispatcher found at maturity 4
2025-07-21 14:39:20,966 - D810.optimizer - DEBUG - [fold_const] New MBA detected! 1689411910336
2025-07-21 14:39:20,966 - D810.optimizer - DEBUG - [fold_const] Checking ins @ 0x1800D36AF (opcode=mov) l=call $sub_18000ECE0<fast:"int n0x3E" #0x3E.4,"__int64 a2" %arg_20.8,"int n0x55" #0x55.4,"int n0x57" #0x57.4,"unsigned int n8" r9d.4>.8 r=
call $sub_18000ECE0<fast:"int n0x3E" #0x3E.4,"__int64 a2" %arg_20.8,"int n0x55" #0x55.4,"int n0x57" #0x57.4,"unsigned int n8" r9d.4>.8 d=call $sub_18000ECE0<fast:"int n0x3E" #0x3E.4,"__int64 a2" %arg_20.8,"int n0x55" #0x55.4,"int n0x57" #0x57.
4,"unsigned int n8" r9d.4>.8
2025-07-21 14:39:20,966 - D810.optimizer - DEBUG - [fold_const] AST for ins: AstProxy(AstConstant(0x3e))
2025-07-21 14:39:20,967 - D810.optimizer - DEBUG - [fold_const] _eval_subtree result: 62
2025-07-21 14:39:20,967 - D810.optimizer - INFO - [fold_const] Collapsed ins at 0x1800D36AF to constant 0x3E (opcode=mov)
2025-07-21 14:39:20,967 - D810.optimizer - INFO - Rule FoldPureConstantRule matched in maturity MMAT_GLBOPT1:
2025-07-21 14:39:20,967 - D810.optimizer - INFO -   orig:  mov      call $sub_18000ECE0<fast:"int n0x3E"  #0x3E.4 ,"__int64 a2" %arg_20.8,"int n0x55"  #0x55.4 ,"int n0x57"  #0x57.4 ,"unsigned int n8" r9d.4>.8 , rax.8
2025-07-21 14:39:20,967 - D810.optimizer - INFO -   new :  ldc      #0x3E.8 , rax.8
2025-07-21 14:39:20,967 - D810.optimizer - DEBUG - [fold_const] New MBA detected! 1689411910656
2025-07-21 14:39:20,967 - D810.optimizer - DEBUG - [fold_const] Skipping mov with constant source (would create infinite loop)
2025-07-21 14:39:20,967 - D810.optimizer - DEBUG - [fold_const] blk is None, ins @ 0x1800D36AF with opcode: mov
2025-07-21 14:39:20,967 - D810.optimizer - DEBUG - [fold_const] Skipping mov with constant source (would create infinite loop)
```

