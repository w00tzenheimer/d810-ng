# Refactoring D810

This codebase is a classic example of deep inheritance hierarchies leading to God objects and tight coupling, making it difficult to test and maintain.

## Composition over Inheritance

Using modern Python principles to favor composition over inheritance, improve testability, and increase clarity, this project can be refactored to be testable and easier to follow.

### Core Problems Identified

1. **Deep Inheritance:** Chains like `Unflattener` -> `GenericDispatcherUnflatteningRule` -> `GenericUnflatteningRule` -> `FlowOptimizationRule` create "God Objects" that know and do too much.
2. **Implicit State:** Rules heavily rely on instance variables (`self.mba`, `self.cur_maturity`, `self.last_pass_nb_patch_done`) that are modified during execution. This makes them stateful and hard to test in isolation.
3. **Mixed Concerns:** A single class like `GenericDispatcherUnflatteningRule` is responsible for finding dispatchers, analyzing control flow, duplicating blocks, and patching the graph.
4. **Poorly Defined Interfaces:** It's not immediately clear what constitutes an "optimization rule" without reading the implementation of the optimizer that runs it.

### Refactoring Strategy: Composition, Protocols, and Statelessness

The goal is to break down large classes into smaller, single-responsibility components and define clear contracts between them.

### 1. Define Clear Interfaces with Protocols

Instead of relying on concrete base classes, define the expected behavior using `typing.Protocol`. This decouples the rules from their execution engine.

```python
# d810/optimizers/core.py (a new file for core abstractions)
import abc
from typing import Protocol, List, Any, Dict
from dataclasses import dataclass
from ida_hexrays import mba_t, mblock_t, minsn_t

@dataclass(frozen=True)
class OptimizationContext:
    """A context object holding all necessary data for an optimization pass."""
    mba: mba_t
    maturity: int
    config: Dict[str, Any]
    logger: logging.Logger
    log_dir: str

class OptimizationRule(Protocol):
    """A contract for any optimization rule."""
    
    @property
    def name(self) -> str:
        """A unique name for the rule."""
        ...

    def apply(self, context: OptimizationContext, element: Any) -> int:
        """
        Applies the optimization.
        
        Args:
            context: The current optimization context.
            element: The program element to optimize (e.g., mblock_t, minsn_t).
        
        Returns:
            The number of changes made.
        """
        ...

class PatternMatchingRule(abc.ABC):
    """An abstract base class for rules that match AST patterns."""
    
    @property
    @abc.abstractmethod
    def pattern(self) -> "AstNode": ...
    
    @property
    @abc.abstractmethod
    def replacement(self) -> "AstNode": ...

    @abc.abstractmethod
    def check_candidate(self, candidate: "AstNode") -> bool:
        """Performs rule-specific checks on a matched pattern."""
        ...

    def apply(self, context: OptimizationContext, ins: minsn_t) -> int:
        """Applies the pattern matching rule to a single instruction."""
        # Implementation for matching `self.pattern` and creating `self.replacement`
        # This can be a shared implementation.
        ...
```

### 2. Decompose God Objects into Composable Services

The monolithic `GenericDispatcherUnflatteningRule` can be broken down into distinct, reusable services.

**Before:** A single, massive class.

```python
class GenericDispatcherUnflatteningRule(GenericUnflatteningRule):
    # ... 200+ lines of finding, analyzing, duplicating, resolving, patching ...
    def optimize(self, blk: mblock_t) -> int:
        self.mba = blk.mba
        # ... lots of state changes and mixed logic ...
```

**After:** A coordinator rule that *uses* specialized services.

```python
# In a new file, e.g., d810/optimizers/flow/flattening/components.py

from typing import NamedTuple

# Use dataclasses or NamedTuples for structured data
@dataclass(frozen=True)
class Dispatcher:
    """Represents a discovered control-flow flattening dispatcher."""
    entry_block: mblock_t
    state_variable: mop_t
    # ... other relevant info

class DispatcherFinder(Protocol):
    """Finds dispatchers in the microcode."""
    def find(self, context: OptimizationContext) -> List[Dispatcher]: ...

class PathEmulator:
    """Emulates microcode paths to resolve state variables."""
    def resolve_target(self, context: OptimizationContext, from_block: mblock_t, dispatcher: Dispatcher) -> mblock_t:
        # Wraps MopTracker and MicroCodeInterpreter logic
        ...

class CFGPatcher:
    """Applies changes to the control-flow graph."""
    @staticmethod
    def redirect_edge(context: OptimizationContext, from_block: mblock_t, new_target: mblock_t) -> int:
        # Wraps logic from cfg_utils
        ...

# The refactored rule becomes a simple coordinator
# In d810/optimizers/flow/flattening/unflattener.py
class UnflattenerRule(OptimizationRule):
    """Removes O-LLVM style control-flow flattening."""
    name = "OLLVMUnflattener"

    def __init__(self):
        # Dependencies are now explicit. They can be real or mock objects for testing.
        self._finder = OllvmDispatcherFinder()
        self._emulator = PathEmulator()
        self._patcher = CFGPatcher()

    def apply(self, context: OptimizationContext, blk: mblock_t) -> int:
        # The rule only applies once per function, so we check the entry block.
        if blk.serial != 0:
            return 0
            
        changes = 0
        dispatchers = self._finder.find(context)
        for disp in dispatchers:
            for pred_serial in disp.entry_block.predset:
                pred_block = context.mba.get_mblock(pred_serial)
                try:
                    target_block = self._emulator.resolve_target(context, pred_block, disp)
                    changes += self._patcher.redirect_edge(context, pred_block, target_block)
                except Exception as e:
                    context.logger.warning(f"Could not unflatten from {pred_block.serial}: {e}")
        return changes
```

### 3. Refactor Pattern Matching with `abc.ABC`

The many `rewrite_*.py` files define rules that are very similar. An abstract base class is perfect here.

**Before:** Each rule class re-implements `check_candidate` and has boilerplate `PATTERN` and `REPLACEMENT_PATTERN` attributes.

**After:** A clear, abstract definition of a pattern rule.

```python
# In d810/optimizers/instructions/pattern_matching/handler.py
class PatternRule(OptimizationRule, abc.ABC):
    """
    An abstract base class for a rule that replaces one AST pattern with another.
    """
    name: str = "UnnamedPatternRule"
    description: str = "No description"

    @property
    @abc.abstractmethod
    def pattern(self) -> AstNode:
        """The AST pattern to match."""
        ...

    @property
    @abc.abstractmethod
    def replacement(self) -> AstNode:
        """The AST pattern to substitute."""
        ...

    def check_candidate(self, candidate: AstNode) -> bool:
        """
        Optional: perform extra validation on a matched pattern.
        By default, a match is always valid.
        """
        return True

    def apply(self, context: OptimizationContext, ins: minsn_t) -> int:
        """Shared implementation to match and replace the pattern."""
        ast = minsn_to_ast(ins)
        if not ast:
            return 0

        if self.pattern.check_pattern_and_copy_mops(ast):
            if self.check_candidate(self.pattern):
                new_ins = self.replacement.create_minsn(ins.ea, ins.d)
                if new_ins:
                    ins.swap(new_ins)
                    return 1
        return 0

# A concrete rule is now extremely concise and declarative.
# In d810/optimizers/instructions/pattern_matching/rewrite_neg.py
class NegToBnotAdd(PatternRule):
    name = "NegToBnotAdd"
    description = "-x => ~x + 1"
    
    @property
    def pattern(self) -> AstNode:
        return AstNode(m_neg, AstLeaf("x"))

    @property
    def replacement(self) -> AstNode:
        return AstNode(m_add, AstNode(m_bnot, AstLeaf("x")), AstConstant("1", 1))
```

### 4. Centralize the Optimizer Loop

Instead of each rule managing its own maturity checks and pass counts, a central `OptimizerManager` should handle the main loop. This manager would instantiate rules and pass them the appropriate `OptimizationContext`.

```python
# In a new file, e.g., d810/manager.py
class OptimizerManager:
    def __init__(self, config: Dict[str, Any]):
        self.flow_rules: List[OptimizationRule] = self._load_rules("flow", config)
        self.instruction_rules: List[OptimizationRule] = self._load_rules("instruction", config)
        # ...

    def _run_optimizers(self, mba: mba_t, maturity: int):
        context = OptimizationContext(mba=mba, maturity=maturity, ...)
        
        # Apply flow rules
        for rule in self.flow_rules:
            # The manager can decide what element to pass (e.g., first block)
            rule.apply(context, mba.get_mblock(0))

        # Apply instruction rules
        for block in mba.blocks:
            for ins in block.instructions:
                for rule in self.instruction_rules:
                    rule.apply(context, ins)

    def install_hooks(self):
        # ... logic to hook into Hex-Rays callbacks and call _run_optimizers ...
```

### Summary of Benefits

* **Testability:** Each component (`OllvmDispatcherFinder`, `PathEmulator`, `NegToBnotAdd`) can be unit-tested in complete isolation by providing mock objects for its dependencies.
* **Maintainability:** Logic is separated by concern. Modifying how dispatchers are found doesn't require touching the patching logic. Adding a new pattern is a small, declarative class.
* **Clarity:** Dependencies are explicit (passed in `__init__` or as method arguments) rather than implicit (`self.mba`). The `Protocol`s serve as clear documentation for how components interact.
* **Reusability:** Components like `CFGPatcher` or `PathEmulator` can be reused by different high-level optimization strategies.

## AstNode construction is imperative instead of declarative

The verbosity of the `AstNode` construction is imperative and low-level. It describes *how* to build the tree, not *what* the tree represents. This makes the rules hard to read and even harder to verify for correctness without running them through a separate test suite. A more declarative, DSL-like approach where the rule's definition is closer to its mathematical proof is the one better approach.

Create a small, embedded DSL using Python's operator overloading. This will make the rules:

1. **Declarative:** You write expressions that look like math, not tree-building code.
2. **Readable:** `(x | y) - (x & y)` is instantly recognizable.
3. **Self-Verifying:** We can build a mechanism to automatically prove the equivalence of the pattern and replacement using Z3, directly from the rule definition.

### Refactoring Plan: A Rule DSL with Built-in Verification

#### 1. Create a Symbolic Expression Layer

First, we'll create a set of classes to represent symbolic variables and expressions. These classes will overload Python's operators (`+`, `-`, `^`, `&`, `|`, `~`) to build the `AstNode` tree behind the scenes.

```python
# d810/optimizers/dsl.py (New File)
from __future__ import annotations
from typing import Dict, Any
from ida_hexrays import mop_t, m_add, m_sub, m_xor, m_and, m_or, m_bnot, m_neg
from d810.expr.ast import AstNode, AstLeaf, AstConstant

class SymbolicExpression:
    """A symbolic representation of a microcode expression tree."""
    def __init__(self, node: AstNode):
        self.node = node

    def __add__(self, other: SymbolicExpression) -> SymbolicExpression:
        return SymbolicExpression(AstNode(m_add, self.node, other.node))

    def __sub__(self, other: SymbolicExpression) -> SymbolicExpression:
        return SymbolicExpression(AstNode(m_sub, self.node, other.node))

    def __xor__(self, other: SymbolicExpression) -> SymbolicExpression:
        return SymbolicExpression(AstNode(m_xor, self.node, other.node))

    def __and__(self, other: SymbolicExpression) -> SymbolicExpression:
        return SymbolicExpression(AstNode(m_and, self.node, other.node))

    def __or__(self, other: SymbolicExpression) -> SymbolicExpression:
        return SymbolicExpression(AstNode(m_or, self.node, other.node))

    def __invert__(self) -> SymbolicExpression:
        return SymbolicExpression(AstNode(m_bnot, self.node))

    def __neg__(self) -> SymbolicExpression:
        return SymbolicExpression(AstNode(m_neg, self.node))

    def __repr__(self) -> str:
        return str(self.node)

def Var(name: str) -> SymbolicExpression:
    """Factory for a symbolic variable."""
    return SymbolicExpression(AstLeaf(name))

def Const(name: str, value: int = 0) -> SymbolicExpression:
    """Factory for a symbolic constant."""
    return SymbolicExpression(AstConstant(name, value))
```

#### 2. Redefine the Rule with the DSL

Now, we can create a new base class for rules that uses this DSL. The key is that it will have a `verify()` method to prove its own correctness.

```python
# d810/optimizers/rules.py (New or Refactored File)
import abc
from typing import List, Dict, Any, Set

from d810.expr.ast import AstNode
from d810.expr.z3_utils import ast_to_z3, z3_prove_equivalence
from d810.optimizers.dsl import SymbolicExpression

# A simple registry to auto-discover all rules
RULE_REGISTRY: List["VerifiableRule"] = []
        
class SymbolicRule(abc.ABC):
    """A rule defined by symbolic, verifiable expressions."""
    name: str = "UnnamedSymbolicRule"
    description: str = "No description"

    @property
    @abc.abstractmethod
    def pattern(self) -> SymbolicExpression:
        """The symbolic pattern to match."""
        ...

    @property
    @abc.abstractmethod
    def replacement(self) -> SymbolicExpression:
        """The symbolic expression to replace the pattern with."""
        ...

    def verify(self) -> bool:
        """
        Proves that `pattern` is equivalent to `replacement` using Z3.
        This makes the rule self-verifying.
        """
        return z3_prove_equivalence(self.pattern.node, self.replacement.node)

    def apply(self, context: OptimizationContext, ins: minsn_t) -> int:
        """Shared implementation to apply the rule."""
        # This logic would be part of the new optimizer
        # It finds a match for `self.pattern.node` and replaces it
        # with a new instruction from `self.replacement.node`.
        ...

class VerifiableRule(abc.ABC):
    """
    An abstract base class for a symbolic rule that can verify its own correctness.
    Subclasses automatically register themselves for testing.
    """
    name: str = "UnnamedVerifiableRule"
    description: str = "No description"
    BIT_WIDTH = 32 # Default bit-width for verification

    def __init_subclass__(cls, **kwargs):
        """Automatically registers any subclass into the global registry."""
        super().__init_subclass__(**kwargs)
        RULE_REGISTRY.append(cls())

    @property
    @abc.abstractmethod
    def pattern(self) -> SymbolicExpression:
        """The symbolic pattern to match, defined using the DSL."""
        ...

    @property
    @abc.abstractmethod
    def replacement(self) -> SymbolicExpression:
        """The symbolic expression to replace the pattern with."""
        ...

    def get_constraints(self, z3_vars: Dict[str, Any]) -> List[Any]:
        """
        Optional: Subclasses can override this to provide Z3 constraints
        under which the rule is valid.
        
        Args:
            z3_vars: A dictionary mapping symbolic variable names to Z3 BitVec objects.
        
        Returns:
            A list of Z3 constraint expressions.
        """
        return []

    def verify(self) -> bool:
        """
        Proves that `self.pattern` is equivalent to `self.replacement` using Z3,
        applying any constraints defined in `get_constraints`.
        
        Returns:
            True if the rule is proven correct, raises an AssertionError otherwise.
        """
        # 1. Get the AST nodes from the symbolic expressions
        p_node = self.pattern.node
        r_node = self.replacement.node

        # 2. Find all unique symbolic variables from both sides
        p_vars = p_node.get_symbolic_vars()
        r_vars = r_node.get_symbolic_vars()
        all_var_names = sorted(list(p_vars.union(r_vars)))

        # 3. Create Z3 BitVec objects for each variable
        z3_vars = {name: BitVec(name, self.BIT_WIDTH) for name in all_var_names}

        # 4. Get rule-specific constraints
        constraints = self.get_constraints(z3_vars)

        # 5. Prove equivalence
        is_equivalent, model = z3_prove_equivalence(
            p_node, r_node, z3_vars, constraints
        )

        if not is_equivalent:
            msg = (
                f"\n--- VERIFICATION FAILED ---\n"
                f"Rule:        {self.name}\n"
                f"Description: {self.description}\n"
                f"Identity:    {self.pattern} => {self.replacement}\n"
                f"Counterexample: {model}"
            )
            raise AssertionError(msg)
        
        return True

```

#### 3. Rewrite Existing Rules Declaratively

Now, the `rewrite_*.py` files become incredibly simple and readable.

**Before (`rewrite_xor.py`):**

```python
class Xor_HackersDelightRule_1(PatternMatchingRule):
    PATTERN = AstNode(
        m_sub,
        AstNode(m_or, AstLeaf("x_0"), AstLeaf("x_1")),
        AstNode(m_and, AstLeaf("x_0"), AstLeaf("x_1")),
    )
    REPLACEMENT_PATTERN = AstNode(m_xor, AstLeaf("x_0"), AstLeaf("x_1"))
```

**After (`rewrite_xor.py`):**

```python
from d810.optimizers.dsl import Var
from d810.optimizers.rules import VerifiableRule

# Define symbolic variables once for the module
x, y = Var("x"), Var("y")

class XorFromOrAndSub(VerifiableRule):
    name = "XorFromOrAndSub"
    description = "(x | y) - (x & y) => x ^ y"

    @property
    def pattern(self) -> SymbolicExpression:
        return (x | y) - (x & y)

    @property
    def replacement(self) -> SymbolicExpression:
        return x ^ y
```

**Before (`rewrite_neg.py`):**

```python
class Neg_HackersDelightRule_1(PatternMatchingRule):
    PATTERN = AstNode(m_add, AstNode(m_bnot, AstLeaf("x_0")), AstConstant("1", 1))
    REPLACEMENT_PATTERN = AstNode(m_neg, AstLeaf("x_0"))
```

**After (`rewrite_neg.py`):**

```python
from d810.optimizers.dsl import Var, Const
from d810.optimizers.rules import SymbolicRule

x = Var("x")
one = Const("one", 1)

class NegFromBnotAdd(SymbolicRule):
    name = "NegFromBnotAdd"
    description = "~x + 1 => -x"

    @property
    def pattern(self) -> SymbolicExpression:
        return ~x + one

    @property
    def replacement(self) -> SymbolicExpression:
        return -x
```

**After (`rewrite_cst.py`):**

```python
# d810/optimizers/instructions/pattern_matching/rewrite_cst.py
from d810.optimizers.dsl import Var, Const
from d810.optimizers.rules import VerifiableRule

x = Var("x")
c1 = Const("c1")
c2 = Const("c2")

class CstSimplification5(VerifiableRule):
    name = "CstSimplification5"
    description = "((x & c1) | (x & c2)) => (((x ^ x) & c1) ^ x) where c2 = ~c1"

    @property
    def pattern(self):
        # Note: The original rule had x1, but the logic implies the same variable.
        # Let's assume it's (x & c1) | (x & c2)
        return (x & c1) | (x & c2)

    @property
    def replacement(self):
        # The original replacement was complex. A simpler equivalent is (x & c1) | (x & ~c1)
        # which simplifies to just x. Let's use the original for demonstration.
        return ((x ^ x) & c1) ^ x

    def get_constraints(self, z3_vars):
        # This rule is only valid if c2 is the bitwise NOT of c1.
        return [z3_vars["c2"] == ~z3_vars["c1"]]
```

### How This Solves the Problem

1. **Correctness is Built-in:**  Instead of manually writing a test case for every rule, one can write a single, generic test that iterates through all `SymbolicRule` instances and call their `verify()` method.

    ```python
    # test/test_rules.py
    import unittest
    import pytest
    from d810.optimizers.rules import VerifiableRule, RULE_REGISTRY

    # You would need to ensure all rule modules are imported so the registry populates.
    # A simple way is an __init__.py file in the rules directory that imports all rule files.
    import d810.optimizers.instructions.pattern_matching.rewrite_xor
    import d810.optimizers.instructions.pattern_matching.rewrite_cst
    # ... import all other rule files ...


    @pytest.mark.parametrize("rule", RULE_REGISTRY, ids=lambda r: r.name)
    def test_rule_is_correct(rule: VerifiableRule):
        """
        This single, generic test verifies the mathematical correctness of every
        rule that inherits from VerifiableRule by calling its own verify() method.
        """
        # The assertion and error message are now handled inside the rule itself.
        # This keeps the test clean and the failure output rich.
        rule.verify()

    class SanityCheck(unittest.TestCase):
        def test_registry_is_populated(self):
            self.assertGreater(len(RULE_REGISTRY), 0, "No rules were discovered and registered.")
    ```

    BONUS: If a developer writes a new rule where the pattern and replacement are not equivalent, this test will fail immediately, preventing incorrect optimizations from ever being merged.

2. **Readability and Intent:** The rule definitions are now high-level and mathematical. The code `(x | y) - (x & y)` is a direct translation of the logic, making the intent clear without needing to parse a complex `AstNode` structure. This approach transforms the rule system from a collection of imperative tree-building instructions into a declarative, self-verifying library of mathematical equivalences. Each rule is responsible for guaranteeing its own correctness. This is a powerful design principle that leads to more robust and reliable systems.

3. **Testability:** The rule's class definition is the complete specification. Its logic, its constraints, and the means to prove its correctness are all in one place. The test suite is now trivial. It doesn't need to be updated when you add new rules. As long as a new rule inherits from VerifiableRule, it will be automatically discovered and tested.
