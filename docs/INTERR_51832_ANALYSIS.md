# INTERR 51832 根因分析与缓解指南

## 背景

某些控制流扁平化函数在 D-810 反混淆过程中触发 IDA Hex-Rays 的
`INTERR 51832`（macro-instruction type mismatch），导致反编译中断。
该错误由 IDA C++ 层直接抛出，**Python 的 `try/except` 无法捕获**。

本文档记录根因分析、已实施的防御机制，以及后续彻底修复所需的工作。

## 典型触发场景

**函数特征**：控制流扁平化使用 **双变量状态机**。

**伪代码模式**：
```c
int primary_state = INIT_CONST;    // 主状态变量，真正被赋值
int64 shadow_state_holder;          // 影子状态所在变量
while (1) {
    HIDWORD(shadow_state_holder) = primary_state;  // 主 → 影子
    switch (HIDWORD(shadow_state_holder)) {         // 用影子分派
    case CONST_A: ...; primary_state = NEXT_A; break;
    case CONST_B: ...; primary_state = NEXT_B; break;
    // ...
    }
}
```

**microcode 典型指令链**：
```
mov primary_state, dl        ; dl ← 主状态寄存器
mov HIDWORD(shadow), dl      ; 影子 ← dl（跨寄存器中转）
cmp HIDWORD(shadow), #CONST
jz  case_X
```

## 失败日志模式

```
d810.hexrays.tracker - WARNING - pred N is jcond but target M is
  neither cond target K nor fallthrough, skipping duplication+redirect

d810.expr.emulator - WARNING - Can't evaluate instruction:
  'mov %var_X.1{v}, <reg>.1{v}': Variable %var_Y.1{v} of type mop_S is not defined

401130: INTERR 51832
```

## 崩溃链

```
ensure_dispatcher_father_is_resolvable()
  └── get_all_possibles_values() 返回"可解析"（表面上，因为返回值并未
       真正代入 emulator 验证）
  └── duplicate_histories() 成功执行路径展开
        → blk_qty 激增（20 → 113 块），每条父块路径被克隆
  
resolve_dispatcher_father()  [对每个新克隆的 father]
  └── emulate_dispatcher_with_father_history()
        └── eval_instruction("mov target, src_reg") 失败
              原因：%var_Y (primary_state) 在当前追踪的历史路径中
                   没有找到定义点（寄存器中转丢失）
        → 返回 cur_blk（调度器内部块，不是 exit block）
  └── 抛出 NotResolvableFatherException
  
结果：nb_flattened_branches == 0 且 total_duplications > 0
      MBA 处于 "已物理展开但语义未解析" 的半破损状态
      
optimize() 返回正值给 IDA
  └── IDA GLBOPT2 C++ optimizer 接手处理此半破损 MBA
        → INTERR 51832
```

## 根因

### 直接原因

D-810 的 `MopTracker` 在追踪调度器比较变量 `HIDWORD(v5)` 的历史路径时：

1. 沿 CFG 反向收集每条指令
2. 构建 `MopHistory.history`：一条路径上涉及的所有 `mop_t`
3. 通过 `MicroCodeInterpreter` 在此 history 上做符号执行以求具体值

**失败点**：当数据流包含 `mov var, reg` → `reg` 又来自更早的 `mov reg, other_var` 时，
tracker 的 `InstructionDefUseCollector` 可能未把 `other_var` 的定义指令纳入 history
（尤其是 `other_var` 属于**不同的 stack variable** 时，跨变量的 def-use 链需要跨 block 追踪）。

### 为什么 `check_if_histories_are_resolved()` 返回 True

`get_all_possibles_values()` 基于 `MopHistory.get_mop_constant_value()` 的返回值，
但该方法在 emulator 失败时返回 `None`；结合 `check_if_histories_are_resolved()`
可能通过了其他路径的值而忽略失败的路径。**这是算法漏洞**：表面可解析不代表
每条路径的 emulation 都会成功，但 `duplicate_histories` 会在"表面可解析"时就开始展开。

### 为什么 IDA 崩溃

`duplicate_histories` 使用 `mba.copy_block()`、`change_1way_block_successor` 等
IDA microcode API 创建新块并接线。这些修改**物理生效**于 `mba`。当
`resolve_dispatcher_father` 无法把这些新块的 CFG 边替换成直接 goto 时，
MBA 保持着 "N 个重复块都指向调度器入口" 的半展开状态。

IDA 的 C++ GLBOPT2 优化器对 microcode 有**强语义约束**（block 数量、
SSA chain、指令类型等必须匹配），遇到此半展开状态无法处理，触发
INTERR 51832。该 INTERR 在 IDA C++ 内部直接 `abort()`，Python 无法介入。

## 已实施的防御机制

### 1. `remove_empty` 保护 (`cfg_utils.py`)
`mba.remove_empty_and_unreachable_blocks()` 包裹 `try/except RuntimeError`，
避免部分重写的 CFG 触发 50860/51832。

### 2. `optimize_local(0)` 在 GLBOPT1..3 全面禁用
涉及 7 个文件：`generic.py`、`deferred_modifier.py`、
`fix_pred_cond_jump_block.py`、`mba_state_preconditioner.py`、
`unflattener_fake_jump.py`、`unflattener_hodur.py`。`optimize_local`
在早期 GLBOPT 对部分重写的 CFG 会触发无法捕获的 INTERR。

### 3. SSA 链失效通知 (`tracker.py`)
`duplicate_histories()` 修改 CFG 后调用 `mba.mark_chains_dirty()`，
确保 Hex-Rays 重算 SSA 使用-定义链。

### 4. 内部块守卫 (`generic.py`)
`resolve_dispatcher_father` 校验 `emulate_dispatcher_with_father_history`
返回的 `target_blk` 必须是 `dispatcher_exit_blocks` 成员，拒绝内部块。

### 5. CFG 一致性预检 (`cfg_utils.py` + `generic.py`)
- `check_mba_cfg_consistency(mba)` → pred/succ 对称性检查
- `mba_deep_cleaning` 在 GLBOPT1..3 执行 simple-goto 清理前做预检，
  不一致时返回哨兵值 `-1`
- `optimize()` 处理 `-1` 和 `safe_verify` 软失败，设 `_verify_failed=True` 并 `return 0`

### 6. GLBOPT1..3 单 pass 限制 (`generic.py`)
`check_if_rule_should_be_used`：GLBOPT1..3 只允许单 pass，避免累积修改
触发 IDA 内部不变量检查。

### 7. GLBOPT2/3 完全禁用 (`generic.py`)
`remove_flattening`：MMAT_GLBOPT2 / MMAT_GLBOPT3 直接 `return 0`。
MMAT_CALLS 和 MMAT_GLBOPT1 提供主要去混淆能力。

### 8. **Abandoned-duplication 守卫**（最终拦截）(`generic.py`)
`remove_flattening` 循环末尾：
```python
if total_duplications > 0 and nb_flattened_branches == 0 \
   and mba_maturity_unflatten_global_opt_early(self.mba):
    self._verify_failed = True
    return 0
```
这是最后的防线：如果 duplicate 成功但 resolve 全失败，直接返回 0
告诉 IDA "我们没做任何有效修改"，让 IDA 丢弃我们的 CFG 编辑。

## 当前状态

**不崩溃** ✅

对于可解析的扁平化函数（tracker + emulator 能成功推导所有 case 值），
去混淆正常工作。

对于**双变量状态机**（或其他 tracker 追踪限制场景），反混淆无法完成，
但通过 Abandoned-duplication 守卫优雅降级——反编译不中断，原函数直接
显示混淆后的代码。

## 后续彻底修复方案

### 方案 A：EmulationFeasibility 预检（推荐，低风险）

在 `ensure_dispatcher_father_is_resolvable()` 的 `duplicate_histories`
**之前**，先对每条 `father_history` 做一次 dry-run emulation：

```python
# 伪代码
def _check_histories_emulate_successfully(father_histories):
    for hist in father_histories:
        interp = MicroCodeInterpreter(symbolic_mode=False)
        env = MicroCodeEnvironment()
        for blk_info in hist.history:
            for ins in blk_info.ins_list:
                if not interp.eval_instruction(blk_info.blk, ins, env):
                    return False  # emulation would fail
    return True

# 使用
if not self._check_histories_emulate_successfully(father_histories):
    raise NotDuplicableFatherException("emulation pre-check failed")
```

**优势**：在展开 CFG 之前就知道是否会失败，彻底避免半展开状态。
**工作量**：~50 行代码，所有路径共享 emulator 实例。
**风险**：多一次 emulation 开销；需验证不会误判合法函数。

### 方案 B：寄存器桥接（中等工作量）

扩展 `InstructionDefUseCollector` 和 `MopTracker.search_backward`，
使其在遇到 `mov var, reg` 时：

1. 从 `blk.build_use_list(ins, FULL_XDSU)` 获取该指令的 use mop
2. 如 use 包含 `mop_r`，继续向上搜索该寄存器的定义点
3. 将定义它的指令（如 `mov reg, other_var`）也纳入 `history`

**优势**：真正解决双变量状态机问题，可去混淆当前失败的函数。
**工作量**：~200 行代码，需完善单元测试。
**风险**：tracker 深度增加可能触发新的路径爆炸；需增设深度/时间预算。

### 方案 C：多变量联合追踪（高工作量）

重构 `MopTracker` 支持同时追踪一组相关 mop（例如：调度器比较变量 + 所有
state-updating 变量）。

**优势**：最完整的解决方案，可处理任意复杂度的多变量状态机。
**工作量**：500+ 行，涉及核心算法改造。
**风险**：回归风险大；需全量回归测试。

### 方案 D：识别并跳过双变量模式（低风险快速方案）

在 dispatcher detection 阶段识别 "比较变量与赋值变量不同" 的扁平化
（即双变量模式），直接标记为 D-810 不支持并跳过。

**优势**：最小化代码修改，避免浪费计算。
**工作量**：~30 行检测代码。
**缺点**：放弃此类函数的去混淆（但本质上当前已是放弃状态）。

## 推荐实施顺序

1. **短期**（本周）：方案 A——EmulationFeasibility 预检。
   避免浪费 CFG 修改，提前失败，保留诊断信息。

2. **中期**（本月）：方案 B——寄存器桥接。
   尝试解决当前失败的函数，扩展 D-810 能力边界。

3. **长期**（按需）：方案 C——多变量联合追踪。
   仅在遇到方案 B 无法处理的新场景时实施。

## 测试样本

- `0x401130`（双变量状态机），`printf("...")` 调用被混淆隐藏
- IDA 伪代码特征：`HIDWORD(v5) = v6;` 模式
- dispatcher 识别为 `CONDITIONAL_CHAIN`，7 个状态常量

此函数当前**崩溃于 INTERR 51832**（已缓解，不崩溃但无去混淆效果）。
验证方案 A/B/C 正确性时应以此函数能正确去混淆为通过标准。

## 日志签名

检测本问题是否出现的日志关键词：

- `pred N is jcond but target M is neither cond target`  ← `duplicate_histories` 开始
- `Can't evaluate instruction ... Variable %var_Y ... is not defined`  ← emulator 失败
- `Abandoned duplication detected for dispatcher ... 0 fathers resolved`  ← 守卫触发
- `Skipping post-unflattening cleanup because MBA verify failed during deferred modifications`

若出现最后一条且**之后**仍 `INTERR 51832`，说明守卫被绕过，需要添加新的防御点。

## 相关文件清单

| 文件 | 主要角色 |
|------|----------|
| `src/d810/hexrays/tracker.py` | `MopTracker`、`duplicate_histories` |
| `src/d810/hexrays/cfg_utils.py` | `mba_deep_cleaning`、`check_mba_cfg_consistency`、`safe_verify` |
| `src/d810/hexrays/deferred_modifier.py` | `DeferredGraphModifier` CFG 修改队列 |
| `src/d810/expr/emulator.py` | `MicroCodeInterpreter`、`MicroCodeEnvironment` |
| `src/d810/optimizers/microcode/flow/flattening/generic.py` | 主去扁平化规则 + 所有 maturity 守卫 |
| `src/d810/optimizers/microcode/flow/flattening/fix_pred_cond_jump_block.py` | 条件跳转前驱修复 |
| `src/d810/optimizers/microcode/flow/flattening/mba_state_preconditioner.py` | MBA 状态预处理 |
| `src/d810/optimizers/microcode/flow/flattening/unflattener_fake_jump.py` | 假跳转去扁平化 |
| `src/d810/optimizers/microcode/flow/flattening/unflattener_hodur.py` | Hodur 变体去扁平化 |
