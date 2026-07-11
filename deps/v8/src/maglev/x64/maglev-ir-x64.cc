// Copyright 2022 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/base/logging.h"
#include "src/codegen/interface-descriptors-inl.h"
#include "src/codegen/x64/assembler-x64-inl.h"
#include "src/codegen/x64/assembler-x64.h"
#include "src/codegen/x64/register-x64.h"
#include "src/maglev/maglev-assembler-inl.h"
#include "src/maglev/maglev-graph-processor.h"
#include "src/maglev/maglev-graph.h"
#include "src/maglev/maglev-ir-inl.h"
#include "src/maglev/maglev-ir.h"
#include "src/objects/feedback-cell.h"
#include "src/objects/instance-type.h"
#include "src/objects/js-function.h"
#include "src/objects/shared-function-info-inl.h"
#include "src/interpreter/bytecode-register.h"
#include "src/runtime/runtime.h"

namespace v8 {
namespace internal {
namespace maglev {

#define __ masm->

// ---
// Nodes
// ---

void InlinedAllocation::SetValueLocationConstraints() {
  UseRegister(allocation_block_input());
  if (offset() == 0) {
    DefineSameAsFirst(this);
  } else {
    DefineAsRegister(this);
  }
}

void InlinedAllocation::GenerateCode(MaglevAssembler* masm,
                                     const ProcessingState& state) {
  if (offset() != 0) {
    __ leaq(ToRegister(result()),
            Operand(ToRegister(allocation_block_input()), offset()));
  }
}

void ArgumentsLength::SetValueLocationConstraints() { DefineAsRegister(this); }

void ArgumentsLength::GenerateCode(MaglevAssembler* masm,
                                   const ProcessingState& state) {
  __ movq(ToRegister(result()),
          Operand(rbp, StandardFrameConstants::kArgCOffset));
  __ decl(ToRegister(result()));  // Remove receiver.
}

void RestLength::SetValueLocationConstraints() { DefineAsRegister(this); }

void RestLength::GenerateCode(MaglevAssembler* masm,
                              const ProcessingState& state) {
  Register length = ToRegister(result());
  Label done;
  __ movq(length, Operand(rbp, StandardFrameConstants::kArgCOffset));
  __ subl(length, Immediate(formal_parameter_count() + 1));
  __ j(greater_equal, &done, Label::Distance::kNear);
  __ Move(length, 0);
  __ bind(&done);
  __ UncheckedSmiTagInt32(length);
}

void LoadTypedArrayLength::SetValueLocationConstraints() {
  UseRegister(receiver_input());
  DefineAsRegister(this);
}
void LoadTypedArrayLength::GenerateCode(MaglevAssembler* masm,
                                        const ProcessingState& state) {
  Register object = ToRegister(receiver_input());
  Register result_register = ToRegister(result());
  if (v8_flags.debug_code) {
    __ AssertNotSmi(object);
    __ CmpObjectType(object, JS_TYPED_ARRAY_TYPE, kScratchRegister);
    __ Assert(equal, AbortReason::kUnexpectedValue);
  }
  __ LoadBoundedSizeFromObject(result_register, object,
                               JSTypedArray::kRawByteLengthOffset);
  int shift_size = ElementsKindToShiftSize(elements_kind_);
  if (shift_size > 0) {
    // TODO(leszeks): Merge this shift with the one in LoadBoundedSize.
    DCHECK(shift_size == 1 || shift_size == 2 || shift_size == 3);
    __ shrq(result_register, Immediate(shift_size));
  }
}

void CheckJSDataViewBounds::SetValueLocationConstraints() {
  UseRegister(receiver_input());
  UseRegister(index_input());
}
void CheckJSDataViewBounds::GenerateCode(MaglevAssembler* masm,
                                         const ProcessingState& state) {
  Register object = ToRegister(receiver_input());
  Register index = ToRegister(index_input());
  Register byte_length = kScratchRegister;
  if (v8_flags.debug_code) {
    __ AssertNotSmi(object);
    __ CmpObjectType(object, JS_DATA_VIEW_TYPE, kScratchRegister);
    __ Assert(equal, AbortReason::kUnexpectedValue);
  }

  // Normal DataView (backed by AB / SAB) or non-length tracking backed by GSAB.
  __ LoadBoundedSizeFromObject(byte_length, object,
                               JSDataView::kRawByteLengthOffset);

  int element_size = compiler::ExternalArrayElementSize(element_type_);
  if (element_size > 1) {
    __ subq(byte_length, Immediate(element_size - 1));
    __ EmitEagerDeoptIf(negative, DeoptimizeReason::kOutOfBounds, this);
  }
  __ cmpl(index, byte_length);
  __ EmitEagerDeoptIf(above_equal, DeoptimizeReason::kOutOfBounds, this);
}

int CheckedObjectToIndex::MaxCallStackArgs() const {
  return MaglevAssembler::ArgumentStackSlotsForCFunctionCall(1);
}

void CheckedIntPtrToInt32::SetValueLocationConstraints() {
  UseRegister(input());
  DefineSameAsFirst(this);
}

void CheckedIntPtrToInt32::GenerateCode(MaglevAssembler* masm,
                                        const ProcessingState& state) {
  Register input_reg = ToRegister(input());

  // Copy input(32 bit) to scratch. Is input equal(64 bit) to scratch?
  __ movl(kScratchRegister, input_reg);
  __ cmpq(kScratchRegister, input_reg);
  __ EmitEagerDeoptIf(not_equal, DeoptimizeReason::kNotInt32, this);
}

void CheckFloat64SameValue::SetValueLocationConstraints() {
  UseRegister(target_input());
}
void CheckFloat64SameValue::GenerateCode(MaglevAssembler* masm,
                                         const ProcessingState& state) {
  Label* fail = __ GetDeoptLabel(this, deoptimize_reason());
  MaglevAssembler::TemporaryRegisterScope temps(masm);
  DoubleRegister double_scratch = temps.AcquireScratchDouble();
  DoubleRegister target = ToDoubleRegister(target_input());
  if (value().is_nan()) {
    __ JumpIfNotNan(target, fail);
  } else {
    __ Move(double_scratch, value());
    __ CompareFloat64AndJumpIf(double_scratch, target, kNotEqual, fail, fail);
    if (value().get_scalar() == 0) {  // If value is +0.0 or -0.0.
      Register scratch = temps.AcquireScratch();
      __ movq(scratch, target);
      __ testq(scratch, scratch);
      __ JumpIf(value().get_bits() == 0 ? kNotEqual : kEqual, fail);
    }
  }
}

int BuiltinStringFromCharCode::MaxCallStackArgs() const {
  return AllocateDescriptor::GetStackParameterCount();
}
void BuiltinStringFromCharCode::SetValueLocationConstraints() {
  if (code_input().node()->Is<Int32Constant>()) {
    UseAny(code_input());
  } else {
    UseAndClobberRegister(code_input());
    set_temporaries_needed(1);
  }
  DefineAsRegister(this);
}
void BuiltinStringFromCharCode::GenerateCode(MaglevAssembler* masm,
                                             const ProcessingState& state) {
  Register result_string = ToRegister(result());
  if (Int32Constant* constant = code_input().node()->TryCast<Int32Constant>()) {
    int32_t char_code = constant->value() & 0xFFFF;
    if (0 <= char_code && char_code < String::kMaxOneByteCharCode) {
      __ LoadSingleCharacterString(result_string, char_code);
    } else {
      __ AllocateTwoByteString(register_snapshot(), result_string, 1);
      __ movw(
          FieldOperand(result_string, OFFSET_OF_DATA_START(SeqTwoByteString)),
          Immediate(char_code));
    }
  } else {
    MaglevAssembler::TemporaryRegisterScope temps(masm);
    Register scratch = temps.Acquire();
    Register char_code = ToRegister(code_input());
    __ StringFromCharCode(register_snapshot(), nullptr, result_string,
                          char_code, scratch,
                          MaglevAssembler::CharCodeMaskMode::kMustApplyMask);
  }
}

void Int32AddWithOverflow::SetValueLocationConstraints() {
  UseRegister(left_input());
  if (TryGetInt32ConstantInput(kRightIndex)) {
    UseAny(right_input());
  } else {
    UseRegister(right_input());
  }
  DefineSameAsFirst(this);
}

void Int32AddWithOverflow::GenerateCode(MaglevAssembler* masm,
                                        const ProcessingState& state) {
  Register left = ToRegister(left_input());
  if (!right_input().operand().IsRegister()) {
    auto right_const = TryGetInt32ConstantInput(kRightIndex);
    DCHECK(right_const);
    __ addl(left, Immediate(*right_const));
  } else {
    Register right = ToRegister(right_input());
    __ addl(left, right);
  }
  // None of the mutated input registers should be a register input into the
  // eager deopt info.
  DCHECK_REGLIST_EMPTY(RegList{left} &
                       GetGeneralRegistersUsedAsInputs(eager_deopt_info()));
  __ EmitEagerDeoptIf(overflow, DeoptimizeReason::kOverflow, this);
}

void Int32SubtractWithOverflow::SetValueLocationConstraints() {
  UseRegister(left_input());
  if (TryGetInt32ConstantInput(kRightIndex)) {
    UseAny(right_input());
  } else {
    UseRegister(right_input());
  }
  DefineSameAsFirst(this);
}

void Int32SubtractWithOverflow::GenerateCode(MaglevAssembler* masm,
                                             const ProcessingState& state) {
  Register left = ToRegister(left_input());
  if (!right_input().operand().IsRegister()) {
    auto right_const = TryGetInt32ConstantInput(kRightIndex);
    DCHECK(right_const);
    __ subl(left, Immediate(*right_const));
  } else {
    Register right = ToRegister(right_input());
    __ subl(left, right);
  }
  // None of the mutated input registers should be a register input into the
  // eager deopt info.
  DCHECK_REGLIST_EMPTY(RegList{left} &
                       GetGeneralRegistersUsedAsInputs(eager_deopt_info()));
  __ EmitEagerDeoptIf(overflow, DeoptimizeReason::kOverflow, this);
}

void Int32MultiplyWithOverflow::SetValueLocationConstraints() {
  UseRegister(left_input());
  UseRegister(right_input());
  DefineSameAsFirst(this);
  set_temporaries_needed(1);
}

void Int32MultiplyWithOverflow::GenerateCode(MaglevAssembler* masm,
                                             const ProcessingState& state) {
  Register result = ToRegister(this->result());
  Register right = ToRegister(right_input());
  DCHECK_EQ(result, ToRegister(left_input()));

  MaglevAssembler::TemporaryRegisterScope temps(masm);
  Register saved_left = temps.Acquire();
  __ movl(saved_left, result);
  // TODO(leszeks): peephole optimise multiplication by a constant.
  __ imull(result, right);
  // None of the mutated input registers should be a register input into the
  // eager deopt info.
  DCHECK_REGLIST_EMPTY(RegList{saved_left, result} &
                       GetGeneralRegistersUsedAsInputs(eager_deopt_info()));
  __ EmitEagerDeoptIf(overflow, DeoptimizeReason::kOverflow, this);

  // If the result is zero, check if either lhs or rhs is negative.
  Label end;
  __ cmpl(result, Immediate(0));
  __ j(not_zero, &end);
  {
    __ orl(saved_left, right);
    __ cmpl(saved_left, Immediate(0));
    // If one of them is negative, we must have a -0 result, which is non-int32,
    // so deopt.
    // TODO(leszeks): Consider splitting these deopts to have distinct deopt
    // reasons. Otherwise, the reason has to match the above.
    __ EmitEagerDeoptIf(less, DeoptimizeReason::kOverflow, this);
  }
  __ bind(&end);
}

void Int32ModulusWithOverflow::SetValueLocationConstraints() {
  UseRegister(left_input());
  UseAndClobberRegister(right_input());
  DefineAsFixed(this, rdx);
  // rax,rdx are clobbered by div.
  RequireSpecificTemporary(rax);
  RequireSpecificTemporary(rdx);
}

void Int32ModulusWithOverflow::GenerateCode(MaglevAssembler* masm,
                                            const ProcessingState& state) {
  // If AreAliased(lhs, rhs):
  //   deopt if lhs < 0  // Minus zero.
  //   0
  //
  // Otherwise, use the same algorithm as in EffectControlLinearizer:
  //   if rhs <= 0 then
  //     rhs = -rhs
  //     deopt if rhs == 0
  //   if lhs < 0 then
  //     let lhs_abs = -lhs in
  //     let res = lhs_abs % rhs in
  //     deopt if res == 0
  //     -res
  //   else
  //     let msk = rhs - 1 in
  //     if rhs & msk == 0 then
  //       lhs & msk
  //     else
  //       lhs % rhs

  Register lhs = ToRegister(left_input());
  Register rhs = ToRegister(right_input());

  static constexpr DeoptimizeReason deopt_reason =
      DeoptimizeReason::kDivisionByZero;

  if (lhs == rhs) {
    // For the modulus algorithm described above, lhs and rhs must not alias
    // each other.
    __ testl(lhs, lhs);
    // TODO(victorgomes): This ideally should be kMinusZero, but Maglev only
    // allows one deopt reason per IR.
    __ EmitEagerDeoptIf(negative, deopt_reason, this);
    __ Move(ToRegister(result()), 0);
    return;
  }

  DCHECK(!AreAliased(lhs, rhs, rax, rdx));

  ZoneLabelRef done(masm);
  ZoneLabelRef rhs_checked(masm);

  __ cmpl(rhs, Immediate(0));
  __ JumpToDeferredIf(
      less_equal,
      [](MaglevAssembler* masm, ZoneLabelRef rhs_checked, Register rhs,
         Int32ModulusWithOverflow* node) {
        __ negl(rhs);
        __ j(not_zero, *rhs_checked);
        __ EmitEagerDeopt(node, deopt_reason);
      },
      rhs_checked, rhs, this);
  __ bind(*rhs_checked);

  __ cmpl(lhs, Immediate(0));
  __ JumpToDeferredIf(
      less,
      [](MaglevAssembler* masm, ZoneLabelRef done, Register lhs, Register rhs,
         Int32ModulusWithOverflow* node) {
        // `divl(divisor)` divides rdx:rax by the divisor and stores the
        // quotient in rax, the remainder in rdx.
        __ movl(rax, lhs);
        __ negl(rax);
        __ xorl(rdx, rdx);
        __ divl(rhs);
        __ negl(rdx);
        __ j(not_zero, *done);
        // TODO(victorgomes): This ideally should be kMinusZero, but Maglev only
        // allows one deopt reason per IR.
        __ EmitEagerDeopt(node, deopt_reason);
      },
      done, lhs, rhs, this);

  Label rhs_not_power_of_2;
  Register mask = rax;
  __ leal(mask, Operand(rhs, -1));
  __ testl(rhs, mask);
  __ j(not_zero, &rhs_not_power_of_2, Label::kNear);

  // {rhs} is power of 2.
  __ andl(mask, lhs);
  __ movl(ToRegister(result()), mask);
  __ jmp(*done, Label::kNear);

  __ bind(&rhs_not_power_of_2);
  // `divl(divisor)` divides rdx:rax by the divisor and stores the
  // quotient in rax, the remainder in rdx.
  __ movl(rax, lhs);
  __ xorl(rdx, rdx);
  __ divl(rhs);
  // Result is implicitly written to rdx.
  DCHECK_EQ(ToRegister(result()), rdx);

  __ bind(*done);
}

void Int32DivideWithOverflow::SetValueLocationConstraints() {
  UseRegister(left_input());
  UseRegister(right_input());
  DefineAsFixed(this, rax);
  // rax,rdx are clobbered by idiv.
  RequireSpecificTemporary(rax);
  RequireSpecificTemporary(rdx);
}

void Int32DivideWithOverflow::GenerateCode(MaglevAssembler* masm,
                                           const ProcessingState& state) {
  Register left = ToRegister(left_input());
  Register right = ToRegister(right_input());
  __ movl(rax, left);

  // TODO(leszeks): peephole optimise division by a constant.

  // Sign extend eax into edx.
  __ cdq();

  // Pre-check for overflow, since idiv throws a division exception on overflow
  // rather than setting the overflow flag. Logic copied from
  // effect-control-linearizer.cc

  // Check if {right} is positive (and not zero).
  __ cmpl(right, Immediate(0));
  ZoneLabelRef done(masm);
  __ JumpToDeferredIf(
      less_equal,
      [](MaglevAssembler* masm, ZoneLabelRef done, Register right,
         Int32DivideWithOverflow* node) {
        // {right} is negative or zero.

        // Check if {right} is zero.
        // We've already done the compare and flags won't be cleared yet.
        // TODO(leszeks): Using kNotInt32 here, but kDivisionByZero would be
        // better. Right now all eager deopts in a node have to be the same --
        // we should allow a node to emit multiple eager deopts with different
        // reasons.
        __ EmitEagerDeoptIf(equal, DeoptimizeReason::kNotInt32, node);

        // Check if {left} is zero, as that would produce minus zero. Left is in
        // rax already.
        __ cmpl(rax, Immediate(0));
        // TODO(leszeks): Better DeoptimizeReason = kMinusZero.
        __ EmitEagerDeoptIf(equal, DeoptimizeReason::kNotInt32, node);

        // Check if {left} is kMinInt and {right} is -1, in which case we'd have
        // to return -kMinInt, which is not representable as Int32.
        __ cmpl(rax, Immediate(kMinInt));
        __ j(not_equal, *done);
        __ cmpl(right, Immediate(-1));
        __ j(not_equal, *done);
        // TODO(leszeks): Better DeoptimizeReason = kOverflow, but
        // eager_deopt_info is already configured as kNotInt32.
        __ EmitEagerDeopt(node, DeoptimizeReason::kNotInt32);
      },
      done, right, this);
  __ bind(*done);

  // Perform the actual integer division.
  __ idivl(right);

  // Check that the remainder is zero.
  __ cmpl(rdx, Immediate(0));
  // None of the mutated input registers should be a register input into the
  // eager deopt info.
  DCHECK_REGLIST_EMPTY(RegList{rax, rdx} &
                       GetGeneralRegistersUsedAsInputs(eager_deopt_info()));
  __ EmitEagerDeoptIf(not_equal, DeoptimizeReason::kNotInt32, this);
  DCHECK_EQ(ToRegister(result()), rax);
}

#define DEF_BITWISE_BINOP(Instruction, opcode)                   \
  void Instruction::SetValueLocationConstraints() {              \
    UseRegister(left_input());                                   \
    if (TryGetInt32ConstantInput(kRightIndex)) {                 \
      UseAny(right_input());                                     \
    } else {                                                     \
      UseRegister(right_input());                                \
    }                                                            \
    DefineSameAsFirst(this);                                     \
  }                                                              \
                                                                 \
  void Instruction::GenerateCode(MaglevAssembler* masm,          \
                                 const ProcessingState& state) { \
    Register left = ToRegister(left_input());                    \
    if (!right_input().operand().IsRegister()) {                 \
      auto right_const = TryGetInt32ConstantInput(kRightIndex);  \
      DCHECK(right_const);                                       \
      __ opcode(left, Immediate(*right_const));                  \
    } else {                                                     \
      Register right = ToRegister(right_input());                \
      __ opcode(left, right);                                    \
    }                                                            \
  }
DEF_BITWISE_BINOP(Int32BitwiseAnd, andl)
DEF_BITWISE_BINOP(Int32BitwiseOr, orl)
DEF_BITWISE_BINOP(Int32BitwiseXor, xorl)
#undef DEF_BITWISE_BINOP

#define DEF_SHIFT_BINOP(Instruction, opcode)                        \
  void Instruction::SetValueLocationConstraints() {                 \
    UseRegister(left_input());                                      \
    if (TryGetInt32ConstantInput(kRightIndex)) {                    \
      UseAny(right_input());                                        \
    } else {                                                        \
      UseFixed(right_input(), rcx);                                 \
    }                                                               \
    DefineSameAsFirst(this);                                        \
  }                                                                 \
                                                                    \
  void Instruction::GenerateCode(MaglevAssembler* masm,             \
                                 const ProcessingState& state) {    \
    Register left = ToRegister(left_input());                       \
    if (auto right_const = TryGetInt32ConstantInput(kRightIndex)) { \
      DCHECK(right_const);                                          \
      int right = *right_const & 31;                                \
      if (right != 0) {                                             \
        __ opcode(left, Immediate(right));                          \
      }                                                             \
    } else {                                                        \
      DCHECK_EQ(rcx, ToRegister(right_input()));                    \
      __ opcode##_cl(left);                                         \
    }                                                               \
  }
DEF_SHIFT_BINOP(Int32ShiftLeft, shll)
DEF_SHIFT_BINOP(Int32ShiftRight, sarl)
DEF_SHIFT_BINOP(Int32ShiftRightLogical, shrl)
#undef DEF_SHIFT_BINOP

void Int32IncrementWithOverflow::SetValueLocationConstraints() {
  UseRegister(value_input());
  DefineSameAsFirst(this);
}

void Int32IncrementWithOverflow::GenerateCode(MaglevAssembler* masm,
                                              const ProcessingState& state) {
  Register value = ToRegister(value_input());
  __ incl(value);
  __ EmitEagerDeoptIf(overflow, DeoptimizeReason::kOverflow, this);
}

void Int32DecrementWithOverflow::SetValueLocationConstraints() {
  UseRegister(value_input());
  DefineSameAsFirst(this);
}

void Int32DecrementWithOverflow::GenerateCode(MaglevAssembler* masm,
                                              const ProcessingState& state) {
  Register value = ToRegister(value_input());
  __ decl(value);
  __ EmitEagerDeoptIf(overflow, DeoptimizeReason::kOverflow, this);
}

void Int32NegateWithOverflow::SetValueLocationConstraints() {
  UseRegister(value_input());
  DefineSameAsFirst(this);
}

void Int32NegateWithOverflow::GenerateCode(MaglevAssembler* masm,
                                           const ProcessingState& state) {
  Register value = ToRegister(value_input());
  // Deopt when the result would be -0.
  __ testl(value, value);
  __ EmitEagerDeoptIf(zero, DeoptimizeReason::kOverflow, this);

  __ negl(value);
  __ EmitEagerDeoptIf(overflow, DeoptimizeReason::kOverflow, this);
}

void Int32AbsWithOverflow::GenerateCode(MaglevAssembler* masm,
                                        const ProcessingState& state) {
  Register value = ToRegister(result());
  Label done;
  __ cmpl(value, Immediate(0));
  __ j(greater_equal, &done);
  __ negl(value);
  __ EmitEagerDeoptIf(overflow, DeoptimizeReason::kOverflow, this);
  __ bind(&done);
}

void Int32BitwiseNot::SetValueLocationConstraints() {
  UseRegister(value_input());
  DefineSameAsFirst(this);
}

void Int32BitwiseNot::GenerateCode(MaglevAssembler* masm,
                                   const ProcessingState& state) {
  Register value = ToRegister(value_input());
  __ notl(value);
}

void Float64Add::SetValueLocationConstraints() {
  UseRegister(left_input());
  UseRegister(right_input());
  DefineSameAsFirst(this);
}

void Float64Add::GenerateCode(MaglevAssembler* masm,
                              const ProcessingState& state) {
  DoubleRegister left = ToDoubleRegister(left_input());
  DoubleRegister right = ToDoubleRegister(right_input());
  __ Addsd(left, right);
}

void Float64Subtract::SetValueLocationConstraints() {
  UseRegister(left_input());
  UseRegister(right_input());
  DefineSameAsFirst(this);
}

void Float64Subtract::GenerateCode(MaglevAssembler* masm,
                                   const ProcessingState& state) {
  DoubleRegister left = ToDoubleRegister(left_input());
  DoubleRegister right = ToDoubleRegister(right_input());
  __ Subsd(left, right);
}

void Float64Multiply::SetValueLocationConstraints() {
  UseRegister(left_input());
  UseRegister(right_input());
  DefineSameAsFirst(this);
}

void Float64Multiply::GenerateCode(MaglevAssembler* masm,
                                   const ProcessingState& state) {
  DoubleRegister left = ToDoubleRegister(left_input());
  DoubleRegister right = ToDoubleRegister(right_input());
  __ Mulsd(left, right);
}

void Float64Divide::SetValueLocationConstraints() {
  UseRegister(left_input());
  UseRegister(right_input());
  DefineSameAsFirst(this);
}

void Float64Divide::GenerateCode(MaglevAssembler* masm,
                                 const ProcessingState& state) {
  DoubleRegister left = ToDoubleRegister(left_input());
  DoubleRegister right = ToDoubleRegister(right_input());
  __ Divsd(left, right);
}

void Float64Modulus::SetValueLocationConstraints() {
  UseRegister(left_input());
  UseRegister(right_input());
  RequireSpecificTemporary(rax);
  DefineAsRegister(this);
}

void Float64Modulus::GenerateCode(MaglevAssembler* masm,
                                  const ProcessingState& state) {
  // Approach copied from code-generator-x64.cc
  // Allocate space to use fld to move the value to the FPU stack.
  __ AllocateStackSpace(kDoubleSize);
  Operand scratch_stack_space = Operand(rsp, 0);
  __ Movsd(scratch_stack_space, ToDoubleRegister(right_input()));
  __ fld_d(scratch_stack_space);
  __ Movsd(scratch_stack_space, ToDoubleRegister(left_input()));
  __ fld_d(scratch_stack_space);
  // Loop while fprem isn't done.
  Label mod_loop;
  __ bind(&mod_loop);
  // This instructions traps on all kinds inputs, but we are assuming the
  // floating point control word is set to ignore them all.
  __ fprem();
  // The following 2 instruction implicitly use rax.
  __ fnstsw_ax();
  if (CpuFeatures::IsSupported(SAHF)) {
    CpuFeatureScope sahf_scope(masm, SAHF);
    __ sahf();
  } else {
    __ shrl(rax, Immediate(8));
    __ andl(rax, Immediate(0xFF));
    __ pushq(rax);
    __ popfq();
  }
  __ j(parity_even, &mod_loop);
  // Move output to stack and clean up.
  __ fstp(1);
  __ fstp_d(scratch_stack_space);
  __ Movsd(ToDoubleRegister(result()), scratch_stack_space);
  __ addq(rsp, Immediate(kDoubleSize));
}

void Float64Negate::SetValueLocationConstraints() {
  UseRegister(input());
  DefineSameAsFirst(this);
}

void Float64Negate::GenerateCode(MaglevAssembler* masm,
                                 const ProcessingState& state) {
  DoubleRegister value = ToDoubleRegister(input());
  __ Negpd(value, value, kScratchRegister);
}

void Float64Abs::GenerateCode(MaglevAssembler* masm,
                              const ProcessingState& state) {
  DoubleRegister out = ToDoubleRegister(result());
  __ Abspd(out, out, kScratchRegister);
}

void Float64Round::GenerateCode(MaglevAssembler* masm,
                                const ProcessingState& state) {
  DoubleRegister in = ToDoubleRegister(input());
  DoubleRegister out = ToDoubleRegister(result());

  if (kind_ == Kind::kNearest) {
    MaglevAssembler::TemporaryRegisterScope temps(masm);
    DoubleRegister temp = temps.AcquireDouble();
    __ Move(temp, in);
    __ Roundsd(out, in, kRoundToNearest);
    // RoundToNearest rounds to even on tie, while JS expects it to round
    // towards +Infinity. Fix the difference by checking if we rounded down by
    // exactly 0.5, and if so, round to the other side.
    __ Subsd(temp, out);
    __ Move(kScratchDoubleReg, 0.5);
    Label done;
    __ Ucomisd(temp, kScratchDoubleReg);
    __ JumpIf(not_equal, &done, Label::kNear);
    // Fix wrong tie-to-even by adding 0.5 twice.
    __ Addsd(out, kScratchDoubleReg);
    __ Addsd(out, kScratchDoubleReg);
    __ bind(&done);
  } else if (kind_ == Kind::kFloor) {
    __ Roundsd(out, in, kRoundDown);
  } else if (kind_ == Kind::kCeil) {
    __ Roundsd(out, in, kRoundUp);
  }
}

int Float64Exponentiate::MaxCallStackArgs() const {
  return MaglevAssembler::ArgumentStackSlotsForCFunctionCall(2);
}
void Float64Exponentiate::SetValueLocationConstraints() {
  UseFixed(left_input(), xmm0);
  UseFixed(right_input(), xmm1);
  DefineSameAsFirst(this);
}
void Float64Exponentiate::GenerateCode(MaglevAssembler* masm,
                                       const ProcessingState& state) {
  AllowExternalCallThatCantCauseGC scope(masm);
  __ PrepareCallCFunction(2);
  __ CallCFunction(ExternalReference::ieee754_pow_function(), 2);
}

int Float64Ieee754Unary::MaxCallStackArgs() const {
  return MaglevAssembler::ArgumentStackSlotsForCFunctionCall(1);
}
void Float64Ieee754Unary::SetValueLocationConstraints() {
  UseFixed(input(), xmm0);
  DefineSameAsFirst(this);
}
void Float64Ieee754Unary::GenerateCode(MaglevAssembler* masm,
                                       const ProcessingState& state) {
  AllowExternalCallThatCantCauseGC scope(masm);
  __ PrepareCallCFunction(1);
  __ CallCFunction(ieee_function_ref(), 1);
}

void HoleyFloat64ToMaybeNanFloat64::SetValueLocationConstraints() {
  UseRegister(input());
  DefineSameAsFirst(this);
}
void HoleyFloat64ToMaybeNanFloat64::GenerateCode(MaglevAssembler* masm,
                                                 const ProcessingState& state) {
  DoubleRegister value = ToDoubleRegister(input());
  // The hole value is a signalling NaN, so just silence it to get the float64
  // value.
  __ Xorpd(kScratchDoubleReg, kScratchDoubleReg);
  __ Subsd(value, kScratchDoubleReg);
}

namespace {

enum class ReduceInterruptBudgetType { kLoop, kReturn };

void HandleInterruptsAndTiering(MaglevAssembler* masm, ZoneLabelRef done,
                                Node* node, ReduceInterruptBudgetType type) {
  // For loops, first check for interrupts. Don't do this for returns, as we
  // can't lazy deopt to the end of a return.
  if (type == ReduceInterruptBudgetType::kLoop) {
    Label next;

    // Here, we only care about interrupts since we've already guarded against
    // real stack overflows on function entry.
    __ cmpq(rsp, __ StackLimitAsOperand(StackLimitKind::kInterruptStackLimit));
    __ j(above, &next);

    // An interrupt has been requested and we must call into runtime to handle
    // it; since we already pay the call cost, combine with the TieringManager
    // call.
    {
      SaveRegisterStateForCall save_register_state(masm,
                                                   node->register_snapshot());
      __ Move(kContextRegister, masm->native_context().object());
      __ Push(MemOperand(rbp, StandardFrameConstants::kFunctionOffset));
      __ CallRuntime(Runtime::kBytecodeBudgetInterruptWithStackCheck_Maglev, 1);
      save_register_state.DefineSafepointWithLazyDeopt(node->lazy_deopt_info());
    }
    __ jmp(*done);  // All done, continue.

    __ bind(&next);
  }

  // No pending interrupts. Call into the TieringManager if needed.
  {
    SaveRegisterStateForCall save_register_state(masm,
                                                 node->register_snapshot());
    __ Move(kContextRegister, masm->native_context().object());
    __ Push(MemOperand(rbp, StandardFrameConstants::kFunctionOffset));
    // Note: must not cause a lazy deopt!
    __ CallRuntime(Runtime::kBytecodeBudgetInterrupt_Maglev, 1);
    save_register_state.DefineSafepoint();
  }
  __ jmp(*done);
}

void GenerateReduceInterruptBudget(MaglevAssembler* masm, Node* node,
                                   Register feedback_cell,
                                   ReduceInterruptBudgetType type, int amount) {
  MaglevAssembler::TemporaryRegisterScope temps(masm);
  __ subl(FieldOperand(feedback_cell, FeedbackCell::kInterruptBudgetOffset),
          Immediate(amount));
  ZoneLabelRef done(masm);
  __ JumpToDeferredIf(less, HandleInterruptsAndTiering, done, node, type);
  __ bind(*done);
}

}  // namespace

int ReduceInterruptBudgetForLoop::MaxCallStackArgs() const { return 1; }
void ReduceInterruptBudgetForLoop::SetValueLocationConstraints() {
  UseRegister(feedback_cell());
}
void ReduceInterruptBudgetForLoop::GenerateCode(MaglevAssembler* masm,
                                                const ProcessingState& state) {
  GenerateReduceInterruptBudget(masm, this, ToRegister(feedback_cell()),
                                ReduceInterruptBudgetType::kLoop, amount());
}

int ReduceInterruptBudgetForReturn::MaxCallStackArgs() const { return 1; }
void ReduceInterruptBudgetForReturn::SetValueLocationConstraints() {
  UseRegister(feedback_cell());
  set_temporaries_needed(1);
}
void ReduceInterruptBudgetForReturn::GenerateCode(
    MaglevAssembler* masm, const ProcessingState& state) {
  GenerateReduceInterruptBudget(masm, this, ToRegister(feedback_cell()),
                                ReduceInterruptBudgetType::kReturn, amount());
}

// ---
// Control nodes
// ---
void Return::SetValueLocationConstraints() {
  UseFixed(value_input(), kReturnRegister0);
}
void Return::GenerateCode(MaglevAssembler* masm, const ProcessingState& state) {
  DCHECK_EQ(ToRegister(value_input()), kReturnRegister0);

  // Read the formal number of parameters from the top level compilation unit
  // (i.e. the outermost, non inlined function).
  int formal_params_size =
      masm->compilation_info()->toplevel_compilation_unit()->parameter_count();

  // We're not going to continue execution, so we can use an arbitrary register
  // here instead of relying on temporaries from the register allocator.
  Register actual_params_size = r8;

  // Compute the size of the actual parameters + receiver (in bytes).
  // TODO(leszeks): Consider making this an input into Return to reuse the
  // incoming argc's register (if it's still valid).
  __ movq(actual_params_size,
          MemOperand(rbp, StandardFrameConstants::kArgCOffset));

  // [DTA] Shadow frame pop is handled by DtaDestroyFrame node emitted in
  // VisitReturn (graph builder), which covers both inlined and non-inlined returns.

  // Leave the frame.
  __ LeaveFrame(StackFrame::MAGLEV);

  // If actual is bigger than formal, then we should use it to free up the stack
  // arguments.
  Label drop_dynamic_arg_size;
  __ cmpq(actual_params_size, Immediate(formal_params_size));
  __ j(greater, &drop_dynamic_arg_size);

  // Drop receiver + arguments according to static formal arguments size.
  __ Ret(formal_params_size * kSystemPointerSize, kScratchRegister);

  __ bind(&drop_dynamic_arg_size);
  // Drop receiver + arguments according to dynamic arguments size.
  __ DropArguments(actual_params_size, r9);
  __ Ret();
}

// ==========================================================================
// DTA (Dynamic Taint Analysis) x64 Code Generation
// ==========================================================================

void DtaShadowRegToAcc::GenerateCode(MaglevAssembler* masm,
                                     const ProcessingState& state) {
  MaglevAssembler::TemporaryRegisterScope temps(masm);
  Register base_reg = temps.Acquire();
  Register taint_reg = temps.Acquire();
  __ Move(base_reg, __ ExternalReferenceAsOperand(
      ExternalReference::taint_shadow_frame_base_address(masm->isolate()),
      base_reg));
  __ movl(taint_reg, Operand(base_reg, reg_operand_ * sizeof(uint32_t)));
  __ movl(__ ExternalReferenceAsOperand(
      ExternalReference::taint_shadow_acc_address(masm->isolate()),
      base_reg), taint_reg);
}

void DtaShadowAccToReg::GenerateCode(MaglevAssembler* masm,
                                     const ProcessingState& state) {
  MaglevAssembler::TemporaryRegisterScope temps(masm);
  Register base_reg = temps.Acquire();
  Register taint_reg = temps.Acquire();
  __ movl(taint_reg, __ ExternalReferenceAsOperand(
      ExternalReference::taint_shadow_acc_address(masm->isolate()),
      base_reg));
  __ Move(base_reg, __ ExternalReferenceAsOperand(
      ExternalReference::taint_shadow_frame_base_address(masm->isolate()),
      base_reg));
  __ movl(Operand(base_reg, reg_operand_ * sizeof(uint32_t)), taint_reg);
}

void DtaShadowRegToReg::GenerateCode(MaglevAssembler* masm,
                                     const ProcessingState& state) {
  MaglevAssembler::TemporaryRegisterScope temps(masm);
  Register base_reg = temps.Acquire();
  Register taint_reg = temps.Acquire();
  __ Move(base_reg, __ ExternalReferenceAsOperand(
      ExternalReference::taint_shadow_frame_base_address(masm->isolate()),
      base_reg));
  __ movl(taint_reg, Operand(base_reg, src_operand_ * sizeof(uint32_t)));
  __ movl(Operand(base_reg, dst_operand_ * sizeof(uint32_t)), taint_reg);
}

void DtaTaintBinaryOp::GenerateCode(MaglevAssembler* masm,
                                    const ProcessingState& state) {
  // Inline OR zero-check fast path + C++ CreateNode slow path.
  // Fast: if (shadow_frame[reg] | shadow_acc) == 0 → skip (both clean).
  // Slow: PropagateBinaryOp(left, right, op_token, result) → new taint node.
  MaglevAssembler::TemporaryRegisterScope temps(masm);
  Register base_reg = temps.Acquire();
  Register scratch = temps.Acquire();
  Label end;

  // Step 1: Load left_taint = shadow_frame[reg_operand_]
  __ Move(base_reg, __ ExternalReferenceAsOperand(
      ExternalReference::taint_shadow_frame_base_address(masm->isolate()),
      base_reg));
  __ movl(scratch, Operand(base_reg, reg_operand_ * sizeof(uint32_t)));

  // Step 2: OR with right_taint = shadow_acc → fast zero-check
  __ orl(scratch, __ ExternalReferenceAsOperand(
      ExternalReference::taint_shadow_acc_address(masm->isolate()),
      kScratchRegister));
  __ testl(scratch, scratch);
  __ j(zero, &end);  // Both clean → skip

  // Step 3 (slow path): Call Runtime to create derived taint node.
  // Args: result_obj (tagged), reg_operand (Smi), op_token (Smi)
  {
    SaveRegisterStateForCall save_register_state(masm, register_snapshot());
    __ Push(ToRegister(result_input()));
    __ Push(Smi::FromInt(reg_operand_));
    __ Push(Smi::FromInt(op_token_));
    __ Move(kContextRegister, masm->native_context().object());
    __ CallRuntime(Runtime::kDtaPropagateBinaryOp, 3);
    save_register_state.DefineSafepoint();
    // rax = Smi(new_taint_id)
    __ SmiUntag(kReturnRegister0);
    __ movl(__ ExternalReferenceAsOperand(
        ExternalReference::taint_shadow_acc_address(masm->isolate()),
        scratch), kReturnRegister0);
  }

  __ bind(&end);
}

void DtaTaintBinaryOpSmi::GenerateCode(MaglevAssembler* masm,
                                       const ProcessingState& state) {
  // Smi right operand has taint 0. shadow_acc = shadow_acc | 0 = shadow_acc.
  // Pure no-op — shadow_acc is already correct. No C++ call needed.
}

void DtaRestoreArgs::GenerateCode(MaglevAssembler* masm,
                                  const ProcessingState& state) {
  // 1. Push shadow frame + set skip stack user-func bit.
  __ Move(kCArgRegs[0], rbp);
  {
    AllowExternalCallThatCantCauseGC scope(masm);
    __ PrepareCallCFunction(1);
    __ CallCFunction(ExternalReference::taint_push_frame_and_leave(), 1);
  }
  // 2. Inline arg taint transfer: arg_buf[i] → shadow_frame[param_i]
  //    Mirrors Ignition's CSA DtaTransferArgTaintsFromBuf but in raw x64.
  MaglevAssembler::TemporaryRegisterScope temps(masm);
  Register count = temps.Acquire();
  Register dst = temps.Acquire();
  Register src = temps.Acquire();
  Label loop, done;

  // Skip the arg-taint transfer entirely when no taint has ever been minted:
  // the arg taint buffer is all zero, so the copy is a no-op. Same inline latch
  // gate used by DtaShadowHeapLoad. (The frame push above is structural and
  // must always run, so it stays outside this guard.)
  __ movzxbl(kScratchRegister, __ ExternalReferenceAsOperand(
      ExternalReference::taint_any_taint_live_address(masm->isolate()),
      kScratchRegister));
  __ testl(kScratchRegister, kScratchRegister);
  __ j(zero, &done);

  // Load arg_count (uint8_t).
  __ movzxbl(count, __ ExternalReferenceAsOperand(
      ExternalReference::taint_arg_count_address(masm->isolate()), count));
  __ testl(count, count);
  __ j(zero, &done);

  // Load shadow_frame_base_ pointer (double indirection via ExternalRef).
  __ movq(dst, __ ExternalReferenceAsOperand(
      ExternalReference::taint_shadow_frame_base_address(masm->isolate()),
      dst));
  __ testq(dst, dst);
  __ j(zero, &done);

  // Offset dst to parameter 0 in the shadow frame.
  // Parameter i lives at shadow_base[kParamOperandBase + i].
  constexpr int kParamOperandBase =
      interpreter::Register::FromParameterIndex(0).ToOperand();
  static_assert(kParamOperandBase > 0,
                "Parameter operand base must be positive for shadow indexing");
  __ leaq(dst, Operand(dst, kParamOperandBase * sizeof(uint32_t)));

  // Load arg taint buffer base address.
  __ Move(src,
          ExternalReference::taint_arg_taint_buf_address(masm->isolate()));

  // Copy loop: one uint32_t per iteration.
  __ bind(&loop);
  __ movl(kScratchRegister, Operand(src, 0));
  __ movl(Operand(dst, 0), kScratchRegister);
  __ addq(src, Immediate(sizeof(uint32_t)));
  __ addq(dst, Immediate(sizeof(uint32_t)));
  __ decl(count);
  __ j(not_zero, &loop);

  __ bind(&done);
}

void DtaDestroyFrame::GenerateCode(MaglevAssembler* masm,
                                   const ProcessingState& state) {
  // [DTA HOF EXTRACT] Call HofExtractOnReturn BEFORE popping the shadow frame.
  // shadow_acc is still valid at this point. The C function checks if the
  // parent call is an HOF with EXTRACT rules and stores taint on the return
  // value object. This mirrors the interpreter's Return handler hook.
  // Note: We pass kReturnRegister0 (rax) which holds the accumulator.
  // [DTA HOF EXTRACT] Fast path: skip C call if shadow_acc == 0 (99.9% of returns)
  {
    Label skip_extract;
    __ movl(kScratchRegister, __ ExternalReferenceAsOperand(
        ExternalReference::taint_shadow_acc_address(masm->isolate()),
        kScratchRegister));
    __ testl(kScratchRegister, kScratchRegister);
    __ j(zero, &skip_extract);
    // Slow path: shadow_acc != 0, call HofExtractOnReturn (GC-safe: no alloc)
    {
      AllowExternalCallThatCantCauseGC scope(masm);
      __ PrepareCallCFunction(1);
      __ movq(kCArgRegs[0], kReturnRegister0);
      __ CallCFunction(ExternalReference::taint_hof_extract_on_return(), 1);
    }
    __ bind(&skip_extract);
  }

  // Inline shadow frame pop — mirrors C++ TaintEngine::PopShadowFrame.
  // Handles sentinel boundary: if (--top <= 0) restore sentinel, else rewind.
  constexpr int kFrameSlotCount = 512;  // Must match TaintEngine::kFrameSlotCount
  constexpr int kFrameByteStride = kFrameSlotCount * sizeof(uint32_t);
  Label sentinel_restore, done;

  // Step 1: Decrement frame_stack_top_ (size_t, 8 bytes).
  __ movq(kScratchRegister, __ ExternalReferenceAsOperand(
      ExternalReference::taint_frame_stack_top_address(masm->isolate()),
      kScratchRegister));
  __ subq(kScratchRegister, Immediate(1));
  __ movq(__ ExternalReferenceAsOperand(
      ExternalReference::taint_frame_stack_top_address(masm->isolate()),
      r9), kScratchRegister);

  // Step 2: Boundary check — if new top <= 0, restore sentinel.
  __ testq(kScratchRegister, kScratchRegister);
  __ j(less_equal, &sentinel_restore);

  // Step 3a (Normal pop): Rewind shadow_frame_base_ by one frame stride.
  __ movq(kScratchRegister, __ ExternalReferenceAsOperand(
      ExternalReference::taint_shadow_frame_base_address(masm->isolate()),
      kScratchRegister));
  __ subq(kScratchRegister, Immediate(kFrameByteStride));
  __ movq(__ ExternalReferenceAsOperand(
      ExternalReference::taint_shadow_frame_base_address(masm->isolate()),
      r9), kScratchRegister);
  __ jmp(&done);

  // Step 3b (Sentinel): Restore sentinel_frame_base_ as the active frame.
  __ bind(&sentinel_restore);
  __ movq(kScratchRegister, __ ExternalReferenceAsOperand(
      ExternalReference::taint_sentinel_frame_base_address(masm->isolate()),
      kScratchRegister));
  __ movq(__ ExternalReferenceAsOperand(
      ExternalReference::taint_shadow_frame_base_address(masm->isolate()),
      r9), kScratchRegister);

  __ bind(&done);
}

void DtaTaintPostCall::GenerateCode(MaglevAssembler* masm,
                                    const ProcessingState& state) {
  MaglevAssembler::TemporaryRegisterScope temps(masm);
  Register scratch1 = temps.Acquire();
  Register scratch2 = temps.Acquire();
  Label skipped, user_func, end;

  // Pop skip stack (skip_top is uint32_t — 32-bit movl)
  // Guard: if skip_top == 0, treat as untracked (jump to skipped)
  __ movl(scratch1, __ ExternalReferenceAsOperand(
      ExternalReference::taint_skip_top_address(masm->isolate()), scratch1));
  __ testl(scratch1, scratch1);
  __ j(zero, &skipped);
  __ decl(scratch1);
  __ movl(__ ExternalReferenceAsOperand(
      ExternalReference::taint_skip_top_address(masm->isolate()), scratch2),
      scratch1);

  // Load entry from skip_stack[new_top] (direct address, no double deref)
  __ Move(scratch2, ExternalReference::taint_skip_stack_address(masm->isolate()));
  __ movzxbl(scratch1, Operand(scratch2, scratch1, times_1, 0));

  __ testl(scratch1, Immediate(0x01));
  __ j(not_zero, &skipped);

  __ testl(scratch1, Immediate(0x02));
  __ j(not_zero, &user_func);

  // Builtin post-hook — Runtime call with ExitFrame + GC safepoint.
  // Uses DeferredCall pattern: SaveRegisterStateForCall protects live regs.
  {
    SaveRegisterStateForCall save_register_state(masm, register_snapshot());
    __ Push(ToRegister(acc_value_input()));
    __ Move(kContextRegister, masm->native_context().object());
    __ CallRuntime(Runtime::kDtaApplyCallRuleTaint, 1);
    save_register_state.DefineSafepoint();
    // rax = Smi(result_taint)
    __ SmiUntag(kReturnRegister0);
    __ movl(__ ExternalReferenceAsOperand(
        ExternalReference::taint_shadow_acc_address(masm->isolate()),
        scratch1), kReturnRegister0);
  }
  __ jmp(&end);

  __ bind(&skipped);
  {
    Label fast_skipped;
    // 0x03 has bit 1 set → fast skip (no EnterCallFrame was called).
    __ testl(scratch1, Immediate(0x02));
    __ j(not_zero, &fast_skipped);
    // 0x01: slow skip → EnterCallFrame was called by C++ prehook, clean up.
    {
      AllowExternalCallThatCantCauseGC scope(masm);
      __ PrepareCallCFunction(0);
      __ CallCFunction(ExternalReference::taint_leave_call_frame_static(), 0);
    }
    __ bind(&fast_skipped);
  }
  // Both paths: clear shadow accumulator taint.
  __ movl(__ ExternalReferenceAsOperand(
      ExternalReference::taint_shadow_acc_address(masm->isolate()),
      scratch1), Immediate(0));
  __ jmp(&end);

  __ bind(&user_func);
  __ bind(&end);
}

void DtaCallPreHook::GenerateCode(MaglevAssembler* masm,
                                  const ProcessingState& state) {
  Register target = ToRegister(target_input());
  // No acquired temps — variable inputs may consume all allocatable registers.
  // Use kScratchRegister (r10, non-allocatable) as primary scratch.
  // Use a C-arg register that doesn't conflict with target as secondary.
  Register scratch1 = (target != kCArgRegs[0]) ? kCArgRegs[0] : kCArgRegs[1];
  Label check_bitmap, fast_skip, smi_runtime, smi_push, slow_path, end;

  // =========================================================================
  // INLINE TIER 0: Smi Runtime ID (O(1) table lookup, no C++ call)
  // =========================================================================
  __ JumpIfSmi(target, &smi_runtime);

  // =========================================================================
  // INLINE TIER 1: SFI TaintSkipBit (writable SFIs — Node.js APIs, etc.)
  // =========================================================================
  __ CmpObjectType(target, JS_FUNCTION_TYPE, scratch1);
  __ j(not_equal, &slow_path);
  __ LoadTaggedField(scratch1, target,
                     JSFunction::kSharedFunctionInfoOffset);
  __ movl(kScratchRegister,
          FieldOperand(scratch1, SharedFunctionInfo::kFlagsOffset));
  __ testl(kScratchRegister, Immediate(static_cast<int32_t>(1u << 31)));
  __ j(not_zero, &fast_skip);

  // =========================================================================
  // INLINE TIER 2: Builtin Bitmap (read-only SFIs — Math.abs, Array.push)
  // =========================================================================
  __ bind(&check_bitmap);
  __ LoadTaggedField(kScratchRegister, scratch1,
                     SharedFunctionInfo::kUntrustedFunctionDataOffset);
  __ JumpIfNotSmi(kScratchRegister, &slow_path);
  __ SmiUntag(kScratchRegister);
  __ testl(kScratchRegister, kScratchRegister);
  __ j(sign, &slow_path);
  // Load bitmap pointer.
  __ movq(scratch1, __ ExternalReferenceAsOperand(
      ExternalReference::taint_builtin_bitmap_ptr_address(masm->isolate()),
      scratch1));
  __ testq(scratch1, scratch1);
  __ j(zero, &slow_path);
  __ movzxbl(scratch1, Operand(scratch1, kScratchRegister, times_1, 0));
  __ testl(scratch1, scratch1);
  __ j(zero, &slow_path);

  // =========================================================================
  // FAST SKIP: Push 0x03 to skip stack (shared by Tier 1 + Tier 2)
  // =========================================================================
  __ bind(&fast_skip);
  __ movl(scratch1, __ ExternalReferenceAsOperand(
      ExternalReference::taint_skip_top_address(masm->isolate()), scratch1));
  __ Move(kScratchRegister, ExternalReference::taint_skip_stack_address(masm->isolate()));
  __ movb(Operand(kScratchRegister, scratch1, times_1, 0), Immediate(0x03));
  __ incl(scratch1);
  __ movl(__ ExternalReferenceAsOperand(
      ExternalReference::taint_skip_top_address(masm->isolate()),
      kScratchRegister), scratch1);
  __ jmp(&end);

  // =========================================================================
  // TIER 0: Smi Runtime ID — three-state O(1) table lookup
  // =========================================================================
  __ bind(&smi_runtime);
  __ SmiUntag(scratch1, target);
  __ movq(kScratchRegister, __ ExternalReferenceAsOperand(
      ExternalReference::taint_runtime_action_table_address(masm->isolate()),
      kScratchRegister));
  __ testq(kScratchRegister, kScratchRegister);
  __ j(zero, &slow_path);
  __ movzxbl(kScratchRegister, Operand(kScratchRegister, scratch1, times_1, 0));
  __ testl(kScratchRegister, kScratchRegister);
  __ j(zero, &slow_path);
  // kScratchRegister is 0x02 (Preserve) or 0x03 (Untracked) — push directly.
  __ bind(&smi_push);
  __ movl(scratch1, __ ExternalReferenceAsOperand(
      ExternalReference::taint_skip_top_address(masm->isolate()), scratch1));
  {
    Register skip_stack = kCArgRegs[0];  // Temporary use — not live here
    __ Move(skip_stack, ExternalReference::taint_skip_stack_address(masm->isolate()));
    __ movb(Operand(skip_stack, scratch1, times_1, 0), kScratchRegister);
  }
  __ incl(scratch1);
  __ movl(__ ExternalReferenceAsOperand(
      ExternalReference::taint_skip_top_address(masm->isolate()),
      kScratchRegister), scratch1);
  __ jmp(&end);

  // =========================================================================
  // SLOW PATH: Runtime call with ExitFrame + GC safepoint.
  // Variable-input: pushes actual tagged arg ValueNodes for GC-safe access.
  // =========================================================================
  __ bind(&slow_path);
  {
    SaveRegisterStateForCall save_register_state(masm, register_snapshot());
    // args[0] = target (tagged function)
    __ Push(target);
    // args[1] = Smi(prepend_receiver)
    __ Push(Smi::FromInt(prepend_receiver_));
    // args[2] = Smi(first_reg_operand) — for shadow frame indexing in C++
    __ Push(Smi::FromInt(first_reg_operand_));
    // args[3..N+2] = actual tagged arg ValueNodes (GC-safe via Arguments)
    for (int i = 0; i < num_args(); i++) {
      detail::PushInput(masm, arg(i));
    }
    __ Move(kContextRegister, masm->native_context().object());
    __ CallRuntime(Runtime::kDtaMaglevCallPreHook, 3 + num_args());
    save_register_state.DefineSafepoint();
  }

  __ bind(&end);
}

void DtaShadowHeapLoad::GenerateCode(MaglevAssembler* masm,
                                     const ProcessingState& state) {
  Label do_query, end;

  // Inline fast path: if no taint has ever been minted (dta_any_taint_live_ ==
  // 0), the shadow heap is empty, so the loaded property/context-slot value
  // cannot carry taint. Skip the unconditional C call and clear shadow_acc.
  // This mirrors the inline zero-check guard the other hot DTA nodes already
  // have (DtaTaintBinaryOp / DtaShadowHeapStore / DtaBindResultTaint). The
  // latch is flipped from the TaintEngine node mint, so it is sound for every
  // taint source (taint() API, source rules, IPC deserialize).
  __ movzxbl(kScratchRegister, __ ExternalReferenceAsOperand(
      ExternalReference::taint_any_taint_live_address(masm->isolate()),
      kScratchRegister));
  __ testl(kScratchRegister, kScratchRegister);
  __ j(not_zero, &do_query);
  // Clean load: result taint is 0 → clear shadow_acc, no C call.
  __ movl(__ ExternalReferenceAsOperand(
      ExternalReference::taint_shadow_acc_address(masm->isolate()),
      kScratchRegister), Immediate(0));
  __ jmp(&end);

  __ bind(&do_query);
  // No temporaries needed — use kCArgRegs[0] as scratch after the call
  __ Move(kCArgRegs[0], ToRegister(object_input()));
  __ Move(kCArgRegs[1], ToRegister(name_input()));
  __ Move(kCArgRegs[2], ToRegister(result_input()));

  {
    AllowExternalCallThatCantCauseGC scope(masm);
    __ PrepareCallCFunction(3);
    __ CallCFunction(ExternalReference::taint_get_named_property(), 3);
  }
  // kCArgRegs[0] (rdi) is caller-saved, use as scratch for the store
  __ movl(__ ExternalReferenceAsOperand(
      ExternalReference::taint_shadow_acc_address(masm->isolate()),
      kCArgRegs[0]), kReturnRegister0);

  __ bind(&end);
}

void DtaBindResultTaint::GenerateCode(MaglevAssembler* masm,
                                      const ProcessingState& state) {
  MaglevAssembler::TemporaryRegisterScope temps(masm);
  Register scratch = temps.Acquire();
  Label end;

  // Fast path: if shadow_acc == 0 (clean result), skip entirely.
  __ movl(scratch, __ ExternalReferenceAsOperand(
      ExternalReference::taint_shadow_acc_address(masm->isolate()), scratch));
  __ testl(scratch, scratch);
  __ j(zero, &end);

  // Slow path: tainted result → bind shadow_acc to result object in shadow heap.
  {
    SaveRegisterStateForCall save_register_state(masm, register_snapshot());
    __ Push(ToRegister(result_input()));
    __ Move(kContextRegister, masm->native_context().object());
    __ CallRuntime(Runtime::kDtaBindResultTaint, 1);
    save_register_state.DefineSafepoint();
  }

  __ bind(&end);
}

void DtaShadowHeapStore::GenerateCode(MaglevAssembler* masm,
                                      const ProcessingState& state) {
  // No acquired temps — use kScratchRegister + a safe C-arg register.
  Register obj_reg = ToRegister(object_input());
  Register name_reg = ToRegister(name_input());
  Register scratch = kScratchRegister;
  Register scratch2 = (obj_reg != kCArgRegs[0] && name_reg != kCArgRegs[0])
                           ? kCArgRegs[0] : kCArgRegs[1];
  Label end;

  // Read value taint (shadow_acc)
  __ movl(scratch, __ ExternalReferenceAsOperand(
      ExternalReference::taint_shadow_acc_address(masm->isolate()), scratch));

  // Read key register taint from shadow frame (if key_reg_operand_ is set)
  if (key_reg_operand_ >= 0) {
    // shadow_frame_base[key_reg_operand_]
    __ movq(scratch2, __ ExternalReferenceAsOperand(
        ExternalReference::taint_shadow_frame_base_address(masm->isolate()),
        scratch2));
    __ movl(scratch2, Operand(scratch2, key_reg_operand_ * sizeof(uint32_t)));
    // Fast path: skip if BOTH value_taint and key_taint are 0
    __ orl(scratch2, scratch);  // scratch2 = value_taint | key_taint
    __ testl(scratch2, scratch2);
    __ j(zero, &end);
  } else {
    // No key register — only check value taint
    __ testl(scratch, scratch);
    __ j(zero, &end);
  }

  // Slow path: at least one taint is non-zero.
  // Re-read value taint (scratch was clobbered by OR)
  __ movl(scratch, __ ExternalReferenceAsOperand(
      ExternalReference::taint_shadow_acc_address(masm->isolate()), scratch));

  {
    SaveRegisterStateForCall save_register_state(masm, register_snapshot());
    __ SmiTag(scratch);
    // Read key taint for 4th arg
    Register key_taint_reg = scratch2;
    if (key_reg_operand_ >= 0) {
      __ movq(key_taint_reg, __ ExternalReferenceAsOperand(
          ExternalReference::taint_shadow_frame_base_address(masm->isolate()),
          key_taint_reg));
      __ movl(key_taint_reg, Operand(key_taint_reg, key_reg_operand_ * sizeof(uint32_t)));
      __ SmiTag(key_taint_reg);
    } else {
      __ Move(key_taint_reg, Smi::zero());
    }
    // Push args: args[0]=object, args[1]=name, args[2]=Smi(value_taint), args[3]=Smi(key_taint)
    __ Push(ToRegister(object_input()));
    __ Push(ToRegister(name_input()));
    __ Push(scratch);
    __ Push(key_taint_reg);
    __ Move(kContextRegister, masm->native_context().object());
    __ CallRuntime(Runtime::kDtaSetNamedPropertyTaint, 4);
    save_register_state.DefineSafepoint();
  }

  __ bind(&end);
}

}  // namespace maglev
}  // namespace internal
}  // namespace v8
