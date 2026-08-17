"""Fail-closed, IDA-free migration of legacy project configurations.

The runtime only consumes typed ``pipeline_v2`` entries.  This module is the
offline compatibility boundary for old project files: it validates the whole
document, projects only known rule ownership, and refuses to guess whenever a
legacy value has no lossless typed representation.

The historical bundled portfolios are deliberately keyed by both basename and
document fingerprint.  Their old rule arrays contain option combinations that
were normalized intentionally when the current v2 canaries were produced; a
nearby custom document must therefore take the strict generic path instead of
inheriting a bundled projection.
"""

from __future__ import annotations

import copy
import base64
import hashlib
import json
import zlib
from collections.abc import Mapping, Sequence
from dataclasses import dataclass

from d810.passes.mba_transform_options import (
    MBA_TRANSFORM_OPTION_FIELDS,
    mba_transform_stages,
)
from d810.passes.pass_pipeline import PipelineConfig, PipelineConfigError
from d810.passes.state_machine_options import STATE_MACHINE_NATIVE_PASS_IDS


class LegacyMigrationError(ValueError):
    """Raised when a legacy project cannot be migrated without loss."""


@dataclass(frozen=True, slots=True)
class LegacyRule:
    """One validated legacy rule entry with a stable source path."""

    section: str
    index: int
    name: str
    options: Mapping[str, object]


@dataclass(frozen=True, slots=True)
class LegacyProject:
    """Validated legacy project data separated from projection/serialization."""

    source_name: str
    description: str
    active_rules: tuple[LegacyRule, ...]
    additional_configuration: Mapping[str, object]
    canonical_fingerprint: str


@dataclass(frozen=True, slots=True)
class KnownPortfolio:
    """Frozen historical source identity and its current pass sequence."""

    source_name: str
    fingerprint: str
    donor_name: str
    pass_ids: tuple[str, ...]


_STATE_MACHINE_PASS_IDS = tuple(str(item) for item in STATE_MACHINE_NATIVE_PASS_IDS)

_NATIVE_SPINE = (
    "recover_dispatcher",
    "recover_state_transitions",
    "plan_semantic_regions",
    "lower_state_machine",
    "cleanup_residual_dispatcher",
)

_JUMP_FIXER_RULE_NAMES = (
    "CompareConstantRule1",
    "CompareConstantRule2",
    "CompareConstantRule3",
    "CompareConstantRule4",
    "JaeRule1",
    "JbRule1",
    "JmpRuleAffineEq",
    "JmpRuleFlagsOpaquePredicate",
    "JmpRuleReachingConst",
    "JmpRuleZ3Const",
    "JnzRule1",
    "JnzRule2",
    "JnzRule3",
    "JnzRule4",
    "JnzRule5",
    "JnzRule6",
    "JnzRule7",
    "JnzRule8",
    "JnzRuleModIdentity",
    "JnzRuleSmodSubIdentity",
    "JnzRuleUmodAddIdentity",
    "JnzRuleUmodSubIdentity",
)
_JUMP_FIXER_RULE_NAME_SET = frozenset(_JUMP_FIXER_RULE_NAMES)

_STATE_RULE_NAME = "StateMachineCffUnflattener"
_JUMP_RULE_NAME = "JumpFixer"
_CONSTANT_RULE_NAMES = frozenset(
    {
        "FoldReadonlyDataRule",
        "ConstantSubtreeFoldRule",
        "ForwardConstantPropagationRule",
    }
)
_CONSTANT_INSTRUCTION_RULE_NAMES = frozenset(
    {"FoldReadonlyDataRule", "ConstantSubtreeFoldRule"}
)

# These are the non-rule project settings consumed by current project/pass
# services.  ``pipeline_v2``, its former mode, and the canary marker are
# handled separately and are never copied to canonical output.
_OWNED_ADDITIONAL_KEYS = frozenset(
    {
        "enable_pass_pipeline",
        "function_analysis_priors",
        "legacy_direct_indirect_materialization",
        "preanalysis_profile_modules",
        "semantic_route_oracle_manifests",
    }
)
_ADDITIONAL_TRANSIENT_KEYS = frozenset(
    {"pipeline_v2", "pipeline_v2_mode", "config_v2_canary"}
)

_RULE_FIELDS = frozenset({"name", "is_activated", "config"})
_MISSING = object()


def _portfolio(
    source_name: str,
    fingerprint: str,
    donor_name: str,
    pass_ids: Sequence[str],
) -> KnownPortfolio:
    return KnownPortfolio(
        source_name=source_name,
        fingerprint=fingerprint,
        donor_name=donor_name,
        pass_ids=tuple(pass_ids),
    )


# Exact historical identities from the approved implementation appendix.
_KNOWN_PORTFOLIOS = (
    _portfolio(
        "default_instruction_only.json",
        "b3f0944b2119e880d2976821953ebf2c50f2646a18a1898ee7ffc0d636c02ab2",
        "default_instruction_only_config_v2_canary.json",
        ("constant-simplification", "mba-simplify", "jump-fixer"),
    ),
    _portfolio(
        "default_unflattening_tigress_engine.json",
        "1d343499a5cb0dec68b2a7efedf3237703dce6fc39b2aae61186feb1a0471db2",
        "default_unflattening_tigress_engine_config_v2_canary.json",
        _NATIVE_SPINE,
    ),
    _portfolio(
        "hodur_flag2.json",
        "2c57256b924f15329eb0166edbfc693f19f56d57a4e317b2c1d03d5458fbc9eb",
        "hodur_flag2_config_v2_canary.json",
        (*_NATIVE_SPINE, "jump-fixer"),
    ),
    _portfolio(
        "hodur_glbopt2_only.json",
        "c6a288756aed1880a54981c5cf596bbb5abddc09e74cefd2c6af60406445c986",
        "hodur_glbopt2_only_config_v2_canary.json",
        _NATIVE_SPINE,
    ),
    _portfolio(
        "eidolon.json",
        "bc241830174e4e5433a0b7d3aaac3f042d56978e9e77c6ed46d000c76cbbcd6c",
        "eidolon_config_v2_canary.json",
        ("mba-simplify",),
    ),
    _portfolio(
        "default_unflattening_approov.json",
        "83f454590e43ae04800cff57670a33e06185cd66ff7daf2141e1f84f62d1c9ac",
        "default_unflattening_approov_config_v2_canary.json",
        (
            "mba-simplify",
            "mba-state-preconditioner",
            *_NATIVE_SPINE,
            "jump-fixer",
        ),
    ),
    _portfolio(
        "default_unflattening_approov_s1a.json",
        "1ca9be3289dd1ef4ec4893434612dbafaed5058bc12b2422ca86218ed51eda05",
        "default_unflattening_approov_s1a_config_v2_canary.json",
        (
            "mba-simplify",
            "mba-state-preconditioner",
            *_NATIVE_SPINE,
            "jump-fixer",
        ),
    ),
    _portfolio(
        "hodur_flag2_s1a.json",
        "11d0f3aa77a291c12715550156585afe577010e865faaf55bdf04b4f2aef2e63",
        "hodur_flag2_s1a_config_v2_canary.json",
        (*_NATIVE_SPINE, "jump-fixer"),
    ),
    _portfolio(
        "hodur_flag2_with_fcp.json",
        "8bbdc05360b7d3f5fe9c345c19a70d8d5269fc0f6d64c5b49bef42ac8e52ae10",
        "hodur_flag2_with_fcp_config_v2_canary.json",
        (
            "mba-simplify",
            *_NATIVE_SPINE,
            "jump-fixer",
            "constant-simplification",
        ),
    ),
    _portfolio(
        "identity_call.json",
        "cd035f21e1ba345d0a6108616344375f1e93866a8cfdee23c6f6770224525339",
        "identity_call_config_v2_canary.json",
        ("identity-call-resolver",),
    ),
    _portfolio(
        "default_unflattening_tigress_engine_transition_facts.json",
        "33a35478e5adcf6b952ec30f30727524a31f721c1d502c89f80165c9b01c4750",
        "default_unflattening_tigress_engine_transition_facts_config_v2_canary.json",
        ("constant-simplification", "mba-simplify", *_NATIVE_SPINE),
    ),
    _portfolio(
        "example_libobfuscated_abc.json",
        "dcf343cfb6ce6f701e5954c64607d8cd8a3512345d1f3057f2be7cf7a006fa5e",
        "example_libobfuscated_abc_config_v2_canary.json",
        (*("constant-simplification", "mba-simplify"), *_NATIVE_SPINE, "jump-fixer"),
    ),
    _portfolio(
        "flatfold.json",
        "fb2f480fcc9088f637a83c9ed5fc9354ed9c40ae61f0fe134ae7f237160d56dd",
        "flatfold_config_v2_canary.json",
        (
            "constant-simplification",
            "mba-simplify",
            "mba-state-preconditioner",
            "jump-fixer",
            *_NATIVE_SPINE,
        ),
    ),
    _portfolio(
        "example_hodur.json",
        "859f94847f7796fb4166b2a7feb70d927a0c54fb50c3f750c7209cddb8c8e6c0",
        "example_hodur_config_v2_canary.json",
        (*("constant-simplification", "mba-simplify"), *_NATIVE_SPINE, "jump-fixer"),
    ),
    _portfolio(
        "default_unflattening_ollvm.json",
        "176a9441b7c866ca37d174c9bf3bcd494521acd94c4ec29c55d115cd951451cb",
        "default_unflattening_ollvm_config_v2_canary.json",
        (
            "constant-simplification",
            "mba-simplify",
            "indirect-call-resolver",
            "mba-state-preconditioner",
            *_NATIVE_SPINE,
            "simple-flattening-cleanup-unflattener",
            "jump-fixer",
        ),
    ),
    _portfolio(
        "default_indirect_resolution.json",
        "3ad2011d8a652b62a1d7c33a4c42f43a9c66f95d8bd4ce42a48f0514baa2a3ee",
        "default_indirect_resolution_config_v2_canary.json",
        ("indirect-branch-resolver", "indirect-call-resolver"),
    ),
    _portfolio(
        "default_unflattening_tigress_indirect.json",
        "2101314f6b7a8213922818e88b4c8aa54d57048aa83dc2c414e6640b74ea9ec9",
        "default_unflattening_tigress_indirect_config_v2_canary.json",
        ("mba-simplify", *_NATIVE_SPINE, "jump-fixer"),
    ),
    _portfolio(
        "default.json",
        "3ad2011d8a652b62a1d7c33a4c42f43a9c66f95d8bd4ce42a48f0514baa2a3ee",
        "default_config_v2_canary.json",
        ("indirect-branch-resolver", "indirect-call-resolver"),
    ),
    _portfolio(
        "example_libobfuscated_no_fixprecedessor.json",
        "9bf4606216bfe471d526b1f12d19cb6da17fdd7a542c51f8283ab350da98c457",
        "example_libobfuscated_no_fixprecedessor_config_v2_canary.json",
        (
            "constant-simplification",
            "mba-simplify",
            "simple-flattening-cleanup-unflattener",
            "jump-fixer",
        ),
    ),
    _portfolio(
        "bogus_loops.json",
        "a1c7a9b5ce95589848c0444413af458e33c599093f722dc89617bbf081a16945",
        "bogus_loops_config_v2_canary.json",
        ("single-trip-loop-peel", "mba-state-preconditioner", "jump-fixer"),
    ),
    _portfolio(
        "example_libobfuscated.json",
        "0e24934ca11872a24d65384967a9830fb567caf2d9b64ae4e15b88ec2d49f546",
        "example_libobfuscated_config_v2_canary.json",
        (
            "constant-simplification",
            "mba-simplify",
            "mba-state-preconditioner",
            *_NATIVE_SPINE,
            "jump-fixer",
        ),
    ),
)
_KNOWN_BY_IDENTITY = {
    (item.source_name, item.fingerprint): item for item in _KNOWN_PORTFOLIOS
}

# Full checked-in donor ``PipelineConfig.to_dict()`` entries and owned
# additional metadata. This compressed JSON blob is the offline fallback once
# donor canaries are deleted; it is intentionally not read from the repository
# at runtime.
_KNOWN_DONOR_TEMPLATE_BLOB = (
    "c-rk<OLOD8(fu!4oBkwHlI__|d}pe@RArM?Hc3sfAQF_3;VUHNk!R}u_cXvKD8QCIl5JUMC7?m#(LjS#pVQ#4$tqiKN<YrByuAER"
    "nWd9Yza~MJMq=&XyMDk@Ry;^qu}LeDaKFqpMZhPYCb`IYEK*LFO)e(2*st%T(w%DmywL9W^zUC2sylutc`2*Ui|k&6Jfwne7n6ej"
    "cO!~AM>nom@SUfjUu2s~Hl1uLR*5Y2n*wT|8m<Z!RI)CS-m_SQtg5T-n~_yVbWz#Vo3LtAh)RtwVOy$M6qoBbTe0{u%W1gcCzq8c"
    "BCX3v9a$;@7Lzb9c*G0U$#fIPR2}s$-&CqiE(eoJJ&oI>+e%*CKh?EH1BR;tma~<JMJ1GEa+hV_eHwdOMp=>gEM$4biwRw6?8L8$"
    "99c$H8dOaUmn`D7M)E8c0i`A(kJu)zCVj8`jC37S#Sx23F7FDmT+YlY&Vui9uGiF|P0VWTPNGd3$VMl<&i!>gKe7*Xk7Vbhf>>Gl"
    "g8DNlMY@i;Qxzh2<VtdK&Ku236{;nm^b^N^t5&+NDmMIL@}1|EuFHg{wE{+~s~)l64)@n&oyDX#zrRe4@?w&*gb&oAhJDAwP0Wk#"
    "?#Yj=_#TT=YD*@gIQ!w36<f<YyXE7zra+az4qyj6b|9z0Z&gp*s9ZBN>uE@ZGtEen6?15PRoo$s((H#q)<FY@oxn~$zMX`dB=<#1"
    "BS?5C=n_8>L6HSn$h-B(Q?`mZEeBeGN(HxBlCy%}QXLgbtG|<cMok&Su37An_^*t&H~w|irP80Hq}wOGJ~{7`i$1yRlUIH6S|*cR"
    "CjaHBUQE7eTfl!v2TmlmAJ6E&X)ld_qGq*uJ$2|Ul3HmRJmkBpRwdqBu@61-y;aadn4ZOzv!cp^JBJ$1;(I)jVG8GK3Z(G(!y3Z="
    "k14-Zh_7_9k;6a2qs!h59%ry&JkIbqgDK!~c96$eNn=x*^s_X6IL@=o)W%6X$fOxI##$%eiHW|ADRwsZ8~z?LELy#M%LAITRm{mG"
    "SSVLTXA%idvZA-030tqJQ>D1)ewz8sYtavCf@;@{J7^p{PAQT+77<xR(<eOU@R-|u%++4`;qFv$wXUd-KRv&BHoT3g@olaa{qGrD"
    "{|p}p`IeD+aA&=d4W#Q9tw>j7Tv0@qO6MzGy1Z!R_pF$F^3-(hUe?RiWfI-^>3B|Ojm>)KjIX)4Egx1;*E#t#mkR7UuO^Fyp|i~j"
    "M|x)4wA-Zb<YF#LCnO75-&Nf;W4Y~m&mx~&<cmh0#qoX8wN~d`E$3;uw!Sjwfnag3qM5D0wH2s})6khY5<i+XxmB7~j$EIuqDC^;"
    "AoC2e`A}xmuC1_bVa+RNljpo}R-!7$eWK(@vfUM#vuy*mUfDWiob%K&=czWgsW!LiaBh_j<OH>|Pz&_lk7cew<{4!3R;KGliMAG5"
    "&g35C$gC!JhncRiaSh`RjypH*Sd(A0dDEm=mx(IS^rrPVl&=A6mMUpbj-TpQ@zf%>UGG}to<%;l$QKs*(jvdI$geH(8?)Tfeb=G}"
    "*P;g3QjbLo7A078U{QfZ0~Q6y@ylIBK8ow5(&t<)C;Oai;^FEZWZfp)uDmuqlzW4;9BRtfj_pBXD|4GNYSMPw_L*gEm9~3K*HblP"
    "Qy+;8S9!alc`eeb(QD9eHg(c6CX?8qmkH568|i{}x|*chC!6;A4ZH7Ob5(Q2yngo#ovA8sl5U^$`sCo+MVpMG{ys{(gS0nDceiG="
    "DrUn>cZclZpolu!=Sp6!v|RdgoOSiAr)TGScA;mNdiHvd)!WgVsaq*G)HSOmG^N^GNiVbCF__(2Fj!=oz-<J!s!VIkB=;<Gskt9q"
    "6!o;#DYr{`U8=us(WRtb)%$5T7MWvll9g4L9Sm%%o6lCaAKT7g+Z9Z5TRn4&e9_2<{clZeJFqpGPI+0$g;8yys2zCo+g{#YYJAx>"
    "7PPNd!5tIw&yD=QbC>W+1f7U(Ym?hS+Wvo|E-RBvzLKWA5J4k~<=&=?YKz#B4MjWuoxbgIx$4K(1KbX9JDdT33*4+TKnXT!6tk-0"
    "DQ$T^%gOe$`(q#l_I3b!!wCu}D4d{hg2D+3Cn%htaDu`K3MVL>pm2i12?{4DoS<-m!U>9C?-Q_-Nhr#kRn$bGT#m7tpdh=ad|%WH"
    "dFUrBxRbTM4-->&?O0eGU#ih4`3sC}Qe-i|94O#8&OS+^r8PJ?UH-6ik|_%s_|BG#g}2n~%($Y?#lqUb*J@Imtf=)@zsmA}p4-__"
    "Iex_o`s?V|tDx~ZipCpU*0W2dL(+BQwJ#Dy-VSJ&t44-tQvOFX)^=~Y9P9W1c5Bq%-nJ}9SjTxalS)G*QQc4VcT&z<?cv|c?hQNB"
    "32p=yTR4mTAdeZTiYKHZ5m0y5YWz<dt!W?lu!dZ#<w)jh)Z`(8dLG+}E>7EW&8zl&td?%=_O0d(*jGA9ctwAgDmJ!Yo5CJ@yFTbU"
    "!a?_jNtn?(VO3Vh#^mX7zDT1?b}uU{t#GiTb%rgshiL7WcP!`9G-xfq`4%HP#KSdzbd%}q$Y05SkYrt4A6dbEXmC9XLkW`ea`>M~"
    "Z_Bn*z5R+g@E+J~;unY67VDkBv@6O@=1n$5!=?Zi8+Mz$e08t5vm7;G`5l@iwNBONa$6JOhL-a=`W@f_2MzdiX~1Cp?#24`%Nctu"
    "=5OB?*uP-^g8d8jFWA3e|APGs_Al7KVE=;s3-&MAzhM7@{R{Rle4p@rg8d8jFWA3l$o{>#_NMbG=)a)<g8qBn^xsEz0`Pyq{{{c|"
    "q)ZnCU=V;o00sg0j0wPoT@egmFo3}Tet&ie3NYN@pa6pc{DCRJie7MZ^6#J(d?FB^2*f7>KhhI=^nMF&Jh<`T#)BIVZald0;KqX+"
    "4{rR&;KqXu4>mm5@L<EA3LActmSUY!{}Z;R%BgS@XR5>C$pat&KyVO%KwJJIt-W-P^awfBZ0${fA;1t2FoJ*)1dJeH<Y?@T+4Ab@"
    "%AMiFc!Z1~WaP|4MjqV@5Hy0I5d@8#nDHWP1Ysix8$sB}8HbG+_eBJbAaDeMBk$2N5jp~g_;X!z?V5>LBI1XSgbXQAlskPyfYXfC"
    ">B0nH7qAP2RGmUdRhRr*7XH6v-$@O0!hg^U%Re@&-GYBo!RIhE7mV&ma#`?qu3l-^YOKBZa}<$%efe)M`IlE;@~vNd{!dRnasyV7"
    "$@%mQ=01-i8A8%NxRvgw+b`F*UvF-`FI3xfJG=6xOYe53GPi#$yyeYusxqGY`Sxac^HpWs#m(*4#p26;4TiK|-6_iZlh>BrOABJw"
    "8e&?#HHeainMESzz9RB8Z|T>w>1DG+mX~*YTd;@nvfUIe6<N?HEz_&5+AjLPw{n|pOq~8Wr6S^Gy&#O2l>f&T%c+0wd45D2p|3`!"
    "E-34uwr{rZx=N@ZCZDHk8s*XB>`cw=A8-d;7Pu^MS>Uq3Wr52Amjx~hTo$-2a9QB8z-58U0+$6Y3tSesEO6Nme<YahL>z3(^+V#7"
    "otT#Paf}#_5!>q+G1@0ZP~pTd0MIx!?3t&A9pOl?Cu8`Zior*~J#aeUbinC=(*dUgP6wP0I2~|0;B>(0fYSk|15O8=4mcffI^cA`"
    ">COnJYmZ%gHDFF}kh&N1H47fvZ?v?<w4+v>{wc?u*SMaS_mA6sER5o#;SxKbLbEO%kp{Jm%lD&3CJzw47fc;LEz(UXPpKXh%Tump"
    "vAirR4EM<sq_qNhZZM6V#g05)Sbpl_(L!fAACxDgJdwu_sw8JcHSl%;)BvafP~*irMIAIxxAeO~{TQm}1Aqqr4*(tjJPx~001N>b"
    "0x;wQ88(0t03`rQ0F;~wP;!tx6Cese6o4qFX0<q=5*Pyx;yd+&_(td7;o!IyG36r6;w(KRCaP8WCvZ&Qn7<icwevO6<}-5XiXO&M"
    ")WlKIrOS&}e$R?wq?LYIFISh%cEhhE+}VD{wN1NC+Vmw_+efZVa?c{4TjYyI-ha}$&$(L8({gQn#!t=~3tU@)*L;h%|D3PPjlZ2e"
    "mbnI*XOPW@GNX2Fg>4J^$AqP1yDKth+bV4B+L|=ZYHFF)RGYn2o4s^6duo(&3R*qa0=@TRnQM@F2HCuo>AF#(twokIxkD(tUX#1S"
    "OxM`BhH(eSof~(o$uHWxX;Q2UK^16v(|R1rc;_`sl{6^FG0j%-)FQWC?^)z?i+o{`FD>#bi~QOmzcI^Q%eY+2xLnsPw+z=ZTFYQ9"
    "W3>#`GEzCvHLo1`<g4et&$(Jo_Bq+a!{s{2x=prSN^M#WDdlVH2j6XFZc}FYh`B7<KC`T?(sqyOda7n@qa%^wDsNXbuSI$_dJX!`"
    "rcPSMWD+|HR8714+G!blkA3htc1cg_cG|vw%~j16^TsLaOjUW4bo->&CkNLq+GG^<_fgs%q`g79yEUU#F&k#OJ7f<BMbyzgSMqA5"
    "<<g(ytgB}|Jv-O43q8Bkv)6;H-j3c(-HK#;&8(Ktlxi;wz07{cV0LT4V3BD8w-MN?GOaC>+_T7~=6-Nd)YDd{+%DyHss6e}my&u_"
    "ua4bVWRAs2R#shhFtDv|K3m;>Y&(N(S1`$K^~^2uMI#^fzcsb(z}93s<z*!oMzx8ecHqr#dwF}Q@jcX7(7qQ1cTC9t4DxTpUBW97"
    "bRxQ~O>PJ2oqr0=2(xfAcrEF(T3MHI&xmNakBgvIs;`uDP)EUT#W=1A#}(nYBDm>sT+s=;(=Lv2B2tk_w9dKXan1`zq;U<OcdbbL"
    ")v1{aPDJLYl$^&b;7+@lI1MQ3WRdfOUMU=rBs>&MO*mYBC*|^!|K>NjTnZ~umE%6aAqa=ydvOT5C+;YO|L`#W!=c=JreD$K?10bl"
    "EqsnMdQ2wtCavCZ;fI7D5`IYdAvHhblgGCvSvWeqHJ1C`&VjCvAMz@{)JQj}zuit7d{#PD=KSPE=7@-NS@A$>M*atKlt;zjB}H5{"
    ";;Io>jl*IQJB`?B#7^U|Sj0yoJ{pI`A_f{U(1?LX3^Zb(aab(koDt`Y!(w5fh-F4BGh&(FIZ-(lt85i*%7B(Ycnrd_p#j;vT3f!F"
    "jIQ4&bCxqm&2LX?W@~j$iS(YPS$j;l@`sjSI^!V@rZbq%U^;{845l-f&R{x&=?tbbn9g82gXs*WGnmd`I)mv9-w6PaC$U1d^;^~Z"
    "wOgo=NUQX2?AnHMMC1}zO+!UaI4iO;A_5Q*a9~(|xmbA1ZpA!Mc|jMf9~2ij+ywOeq7_Jq(a|Od8bHthf(FhmXyA9Z3&a&5t^jcb"
    "AJ4uKdVtUagdQOD;EY2LUb=N6IswrMh)y_B<3#`i{Pzf8Kmfxz1u*z*6&yW?p>G5yup?LjC$Qt$jJSm3#U;Ftpn*g3=bxbPo5BrV"
    "MCf@|pu>=-G-Njo#k)i&1NX>AQ8F=^cKJ>=deoc6TRemF{}OJ$XAU!Xc?87o#A56fA7TBjq!z32NDt=57!rHr#vv&FmWTsuM1d*J"
    ";fe4H?}@MpEwEs(u!rXdRy+~yF}H?}JTKVcBuM)R(s)@k#*4lIHoVRKO?vY4qAi{iPw{wk#&g3MUJ`-v2GJR>9pLa-IELFtIP4t+"
    "VhP&NBRfn{72e)KB=0bU!4PBd!f=pj-;t@>Mqd^rq6L490z*szB*zYb*e?WQpD2)LM11J4E$==0;aOoE^B2WI?1qxq;wwfWCZouV"
    "_OD8k-8*+QP}xeww-sU#z^w+i8mFy;I1S=7h|@T29js`uqQQ#BY3raogYpc@GbqnEZ5@1O@R@PiIxG}qWssFYRz5AVa+>+15P4(_"
    "y#mS?z~fVwElq;R3?eg#%y@2t$P6Mgh|C}|gUAdbGl<L}GK0trA~T50AToo<3?eg#%pfwuPx6X>k`@z-SR&$w6UR5S<*$}LccPe8"
    "6;DOFcABv|o3s%E_k&#k_XF;C+PI(G%%tP>kiec^Cy+ZJclcg19>;+5&Jxah1!(MdKQ;GZJPU8*Q8)wt(`mRZ?cd3Ktq*mYU6)7y"
    "u<7$$<4^muU0`(QhQ%Eb`hM|O!=H~zzW_`>#7EbSAh#Kge?On7H*hE31vSJ(;Mj{UGGKYU6@};Zs9S@1>~ix*XkD*Fp8|-2f2a5&"
    "t@(?zGklR2b^<#AsDfkAa10ubLBla<I0g;Jpy3!a9D{~q&~OYIjzPmQXgCH9$DrXDG#rD5W6*F68jeB3F=+3fJ*~oU{U~N@_mBkY"
    "ooXdfyIs}w`V%E7R!CE&>dVc_zxw+156|<iZ>RHVt$M*4gP3k-*VE~2{+BP)`hAL)Lh45aZ5e_T#EMFE%Ty$^6O^JR?5gY9Vr30w"
    "&EIZCwHy4CdtGlpBHc9mQX{{iMHYwcGqRE1xN@OnSwt&J^^dxL6-A+M>zLfC*aK|}pK3+9S6z{N?GGDvZ{z?Qb+(<jk~8@|&3>f*"
    "?&#X(-YDvJ@%1m>{PXOOo6pNH-fSVCoBI>k;Q)pM7!F`KfZ+g!0~iiqIDp{*h65N5U^sx`0EPn?4q!Nd;Q)pM7!F`qD5%?@ZiBl0"
    "-Vq(YoUtRJI(^ju7XU5*TmZNLZ~@=~zy*K{02cr*09*jL0AC-#1%L|x7XU5*TmZNLZ~@=~zy*K{9|&BKXCM1fkRJ<S(Ca^mL-=vF"
    "_^F&NzH>16V;_`#-cheOK@m_Npgur-fcgOS0qO(P2dEEFAD})!eSrD^^#SSw)CZ^!P#>T^Kz*=KKz)Gv0QJG3@d@j9^9gHu7Z5>p"
    "mS3yh8~$F$E7Gy+OGO?Y{NAk{5q5yx0J{Np1MCLa4X_(vH^6Ry-2l4*c7qojup3}Ez;1xu0J{NpJJ0X8$eFIBR@IU|pfl1?F+y;F"
    "3hs>x`h1)7LP*1s{j3d-W{BQ|SP|R}_dmMJo7RP-ghY0lR#-?zdPgO$X8rB5bmX#hXdHET(zzM_pZ^2qd*-J"
)
_KNOWN_DONOR_TEMPLATES = json.loads(
    zlib.decompress(base64.b85decode(_KNOWN_DONOR_TEMPLATE_BLOB)).decode("utf-8")
)


def _source_basename(source_name: str) -> str:
    """Normalize POSIX and Windows path spellings to a basename."""

    if not isinstance(source_name, str) or not source_name:
        raise LegacyMigrationError("source_name must be a non-empty string")
    return source_name.replace("\\", "/").rsplit("/", 1)[-1]


def _source_path(document: Mapping[str, object]) -> str:
    """Return a stable canonical JSON representation for hashing."""

    try:
        encoded = json.dumps(
            document,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise LegacyMigrationError(
            "document contains a value that is not canonical JSON"
        ) from exc
    return hashlib.sha256(encoded).hexdigest()


def _deep_json_copy(value: object, path: str) -> object:
    """Copy JSON data while rejecting non-JSON values and non-string keys."""

    if value is None or isinstance(value, (str, int, float, bool)):
        if isinstance(value, float) and (value != value or value in (float("inf"), float("-inf"))):
            raise LegacyMigrationError(f"{path} must contain only finite JSON numbers")
        return value
    if isinstance(value, Mapping):
        result: dict[str, object] = {}
        for key, child in value.items():
            if not isinstance(key, str) or not key:
                raise LegacyMigrationError(f"{path} mapping keys must be non-empty strings")
            result[key] = _deep_json_copy(child, f"{path}.{key}")
        return result
    if isinstance(value, (list, tuple)):
        return [_deep_json_copy(child, f"{path}[{index}]") for index, child in enumerate(value)]
    raise LegacyMigrationError(f"{path} must be JSON-compatible")


def _require_mapping(value: object, path: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise LegacyMigrationError(f"{path} must be a mapping")
    return value


def _parse_rules(
    document: Mapping[str, object], section: str
) -> tuple[LegacyRule, ...]:
    raw_rules = document.get(section, [])
    if isinstance(raw_rules, (str, bytes)) or not isinstance(raw_rules, Sequence):
        raise LegacyMigrationError(f"{section} must be a sequence")
    parsed: list[LegacyRule] = []
    for index, raw_rule in enumerate(raw_rules):
        path = f"{section}[{index}]"
        rule = _require_mapping(raw_rule, path)
        unknown = sorted(set(rule).difference(_RULE_FIELDS))
        if unknown:
            raise LegacyMigrationError(f"{path}.{unknown[0]} is not a supported rule field")
        name = rule.get("name", _MISSING)
        if not isinstance(name, str) or not name:
            raise LegacyMigrationError(f"{path}.name must be a non-empty string")
        activated = rule.get("is_activated", _MISSING)
        if not isinstance(activated, bool):
            raise LegacyMigrationError(f"{path}.is_activated must be a boolean")
        options = rule.get("config", _MISSING)
        if not isinstance(options, Mapping):
            raise LegacyMigrationError(f"{path}.config must be a mapping")
        copied = _deep_json_copy(options, f"{path}.config")
        assert isinstance(copied, dict)
        if activated:
            parsed.append(
                LegacyRule(
                    section=section,
                    index=index,
                    name=name,
                    options=copied,
                )
            )
    return tuple(parsed)


def _parse_legacy_document(
    document: Mapping[str, object], *, source_name: str
) -> LegacyProject:
    if not isinstance(document, Mapping):
        raise LegacyMigrationError("document must be a mapping")
    basename = _source_basename(source_name)
    allowed_top = frozenset(
        {"description", "ins_rules", "blk_rules", "additional_configuration"}
    )
    unknown_top = sorted(set(document).difference(allowed_top))
    if unknown_top:
        raise LegacyMigrationError(f"document.{unknown_top[0]} is not a supported field")
    description = document.get("description", "")
    if not isinstance(description, str):
        raise LegacyMigrationError("description must be a string")
    additional = document.get("additional_configuration", {})
    if not isinstance(additional, Mapping):
        raise LegacyMigrationError("additional_configuration must be a mapping")
    copied_additional = _deep_json_copy(additional, "additional_configuration")
    assert isinstance(copied_additional, dict)
    ins_rules = _parse_rules(document, "ins_rules")
    blk_rules = _parse_rules(document, "blk_rules")
    active_rules = (*ins_rules, *blk_rules)
    return LegacyProject(
        source_name=basename,
        description=description,
        active_rules=active_rules,
        additional_configuration=copied_additional,
        canonical_fingerprint=_source_path(document),
    )


def _pipeline_payload(legacy: LegacyProject) -> object:
    return legacy.additional_configuration.get("pipeline_v2", _MISSING)


def _error_for_rule(rule: LegacyRule, message: str, *, field: str | None = None) -> LegacyMigrationError:
    path = f"{rule.section}[{rule.index}]"
    if field:
        path = f"{path}.{field}"
    return LegacyMigrationError(f"{path} ({rule.name}): {message}")


def _typed_error_for_rules(
    rules: Sequence[LegacyRule], message: str
) -> LegacyMigrationError:
    """Attach typed registry failures to their originating legacy rule."""

    if not rules:
        return LegacyMigrationError(message)
    owner = rules[0]
    if len(rules) > 1:
        transform_map = _mba_transform_map()
        for candidate in rules:
            transform_id = transform_map.get(candidate.name)
            if transform_id is not None and transform_id in message:
                owner = candidate
                break
            if any(str(key) in message for key in candidate.options):
                owner = candidate
                break
    field = next(
        (f"config.{key}" for key in owner.options if str(key) in message),
        "config",
    )
    return _error_for_rule(owner, f"typed config-v2 validation failed: {message}", field=field)


def _validate_v2_entries(
    payload: object, *, path_prefix: str, normalize: bool = True
) -> tuple[dict[str, object], ...]:
    if isinstance(payload, (str, bytes)) or not isinstance(payload, Sequence):
        raise LegacyMigrationError(f"{path_prefix} must be a sequence of pass configs")
    if not payload:
        raise LegacyMigrationError(f"{path_prefix} must contain at least one pass config")

    # Importing the operational registry is intentionally lazy.  The module can
    # be imported by offline tooling without importing the entire runtime until
    # a project actually needs typed validation.
    from d810.passes.operational_config_v2 import operational_config_v2_pass_registry

    registry = operational_config_v2_pass_registry()
    entries: list[dict[str, object]] = []
    seen_pass_ids: dict[str, int] = {}
    for index, raw_entry in enumerate(payload):
        path = f"{path_prefix}[{index}]"
        if not isinstance(raw_entry, Mapping):
            raise LegacyMigrationError(f"{path} must be a mapping")
        try:
            config = PipelineConfig.from_dict(raw_entry)
            if config.pass_id in seen_pass_ids:
                previous = seen_pass_ids[config.pass_id]
                raise PipelineConfigError(
                    f"duplicate pass ownership for {config.pass_id!r}; "
                    f"already declared at {path_prefix}[{previous}]"
                )
            registry.build_spec(config)
        except (PipelineConfigError, ValueError, RuntimeError) as exc:
            raise LegacyMigrationError(f"{path}: {exc}") from exc
        seen_pass_ids[config.pass_id] = index
        if normalize:
            # Emit the typed serializer's stable shape rather than preserving
            # enum aliases, omitted defaults, or ``options: null`` from input.
            entries.append(config.to_dict())
        else:
            copied = _deep_json_copy(raw_entry, path)
            assert isinstance(copied, dict)
            entries.append(copied)
    return tuple(entries)


def _normalize_description(description: str, source_name: str) -> str:
    lowered = description.lower()
    if any(token in lowered for token in ("canary", "shadow", "legacy source", "alternate runtime")):
        return f"Canonical config-v2 project for {source_name}"
    if description:
        return description
    return f"Migrated legacy project {source_name} to config-v2"


def _owned_additional(
    additional: Mapping[str, object], *, pipeline: tuple[dict[str, object], ...]
) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in additional.items():
        if key in _ADDITIONAL_TRANSIENT_KEYS:
            continue
        if key not in _OWNED_ADDITIONAL_KEYS:
            raise LegacyMigrationError(
                f"additional_configuration.{key} is not owned by a current pass or editor"
            )
        result[key] = _deep_json_copy(value, f"additional_configuration.{key}")
    result["pipeline_v2"] = [copy.deepcopy(item) for item in pipeline]
    return result


def _canonical_document(
    legacy: LegacyProject,
    entries: tuple[dict[str, object], ...],
) -> dict[str, object]:
    additional = _owned_additional(legacy.additional_configuration, pipeline=entries)
    return {
        "description": _normalize_description(legacy.description, legacy.source_name),
        "additional_configuration": additional,
    }


def _find_rule(rules: Sequence[LegacyRule], name: str) -> LegacyRule | None:
    for rule in rules:
        if rule.name == name:
            return rule
    return None


def _find_rules(rules: Sequence[LegacyRule], name: str) -> tuple[LegacyRule, ...]:
    return tuple(rule for rule in rules if rule.name == name)


def _legacy_rule_path(rule: LegacyRule, field: str) -> str:
    return f"{rule.section}[{rule.index}].config.{field}"


def _copy_option_path(
    target: dict[str, object], path: Sequence[str], value: object
) -> None:
    cursor = target
    for segment in path[:-1]:
        child = cursor.setdefault(segment, {})
        if not isinstance(child, dict):
            raise LegacyMigrationError(f"options.{'.'.join(path)} has conflicting ownership")
        cursor = child
    cursor[path[-1]] = copy.deepcopy(value)


def _mba_transform_map() -> dict[str, str]:
    return {stage.implementation_name: stage.stage_id for stage in mba_transform_stages()}


def _project_transform_options(rule: LegacyRule, transform_id: str) -> dict[str, object]:
    fields = MBA_TRANSFORM_OPTION_FIELDS.get(transform_id, ())
    fields_by_name = {field.path[-1]: field for field in fields if field.path}
    projected: dict[str, object] = {}
    for key, value in rule.options.items():
        field = fields_by_name.get(key)
        if field is None:
            raise _error_for_rule(
                rule,
                f"no typed option exists for MBA transform {transform_id!r}",
                field=f"config.{key}",
            )
        _copy_option_path(projected, field.path, value)
    return projected


def _project_mba_rules(
    rules: Sequence[LegacyRule], *, allow_duplicate_transforms: bool = False
) -> dict[str, object] | None:
    transform_map = _mba_transform_map()
    transforms: list[str] = []
    transform_options: dict[str, object] = {}
    owners: dict[str, LegacyRule] = {}
    for rule in rules:
        transform_id = transform_map.get(rule.name)
        if transform_id is None:
            if rule.name in _CONSTANT_RULE_NAMES or rule.name in {
                _STATE_RULE_NAME,
                _JUMP_RULE_NAME,
                "MbaStatePreconditioner",
                "IdentityCallResolver",
                "IndirectBranchResolver",
                "IndirectCallResolver",
                "SimpleFlatteningCleanupUnflattener",
                "SingleTripLoopPeel",
            }:
                continue
            raise _error_for_rule(rule, "unknown instruction rule", field="name")
        if transform_id in owners and not allow_duplicate_transforms:
            raise _error_for_rule(
                rule,
                f"conflicting duplicate ownership with ins_rules[{owners[transform_id].index}]",
                field="name",
            )
        if transform_id in owners:
            # Historical known portfolios intentionally contained duplicate
            # entries.  Their donor semantics retain the first occurrence.
            continue
        owners[transform_id] = rule
        transforms.append(transform_id)
        options = _project_transform_options(rule, transform_id)
        if options:
            transform_options[transform_id] = options
    if not transforms:
        return None
    options: dict[str, object] = {"transforms": transforms}
    options["transform_options"] = transform_options
    return options


def _constant_options(rules: Sequence[LegacyRule]) -> dict[str, object]:
    fold = _find_rule(rules, "FoldReadonlyDataRule")
    subtree = _find_rule(rules, "ConstantSubtreeFoldRule")
    fcp = _find_rule(rules, "ForwardConstantPropagationRule")
    if fold is None or subtree is None or fcp is None:
        owner = fold or subtree or fcp
        if owner is not None:
            missing = sorted(_CONSTANT_RULE_NAMES.difference({item.name for item in rules}))
            raise _error_for_rule(
                owner,
                "constant-simplification requires the complete owner bundle; "
                f"missing {missing}",
                field="name",
            )
        return {}
    allowed_fold = {"fold_writable_constants", "allow_executable_readonly", "rva_guard"}
    for key in fold.options:
        if key not in allowed_fold:
            raise _error_for_rule(fold, "unsupported constant-fold option", field=f"config.{key}")
    for rule in (subtree, fcp):
        if rule.options:
            key = next(iter(rule.options))
            raise _error_for_rule(rule, "constant bundle does not expose this option", field=f"config.{key}")
    fold_writable = fold.options.get("fold_writable_constants", False)
    if not isinstance(fold_writable, bool):
        raise _error_for_rule(fold, "must be a boolean", field="config.fold_writable_constants")
    options: dict[str, object] = {
        "memory_policy": "aggressive_no_direct_writes" if fold_writable else "strict",
        "allow_executable_readonly": fold.options.get("allow_executable_readonly", False),
    }
    if "rva_guard" in fold.options:
        options["rva_guard"] = fold.options["rva_guard"]
    return options


def _state_options(rule: LegacyRule) -> dict[str, object]:
    allowed = {
        "min_state_constant",
        "family",
        "recovery_strategy",
        "native_cfg_persistence",
    }
    for key in rule.options:
        if key not in allowed:
            raise _error_for_rule(rule, "state-machine option has no typed equivalent", field=f"config.{key}")
    result = dict(rule.options)
    if "native_cfg_persistence" in result and not isinstance(result["native_cfg_persistence"], bool):
        raise _error_for_rule(rule, "must be a boolean", field="config.native_cfg_persistence")
    return result


def _jump_options(rule: LegacyRule) -> dict[str, object]:
    allowed = {"enabled_rules"}
    for key in rule.options:
        if key not in allowed:
            raise _error_for_rule(rule, "jump-fixer option has no typed equivalent", field=f"config.{key}")
    if "enabled_rules" not in rule.options:
        return {}
    enabled = rule.options["enabled_rules"]
    if isinstance(enabled, (str, bytes)) or not isinstance(enabled, Sequence):
        raise _error_for_rule(rule, "must be an ordered list of rule names", field="config.enabled_rules")
    values = list(enabled)
    if any(not isinstance(item, str) for item in values):
        raise _error_for_rule(rule, "must contain only rule names", field="config.enabled_rules")
    unknown = [item for item in values if item not in _JUMP_FIXER_RULE_NAME_SET]
    if unknown:
        raise _error_for_rule(rule, f"unknown rule(s): {unknown}", field="config.enabled_rules")
    if len(values) != len(set(values)):
        raise _error_for_rule(rule, "contains duplicate rule names", field="config.enabled_rules")
    return {"enabled_rules": values}


def _direct_options(rule: LegacyRule, pass_id: str) -> dict[str, object]:
    # ``PipelineConfig`` + the operational registry provide the authoritative
    # field/type validation for direct adapters.  The explicit copy keeps the
    # legacy module independent from their implementation classes.
    if pass_id == "jump-fixer":
        return _jump_options(rule)
    if pass_id in _STATE_MACHINE_PASS_IDS:
        return _state_options(rule)
    if pass_id == "constant-simplification":
        return _constant_options((rule,))
    if pass_id in {"forward-constant-propagation", "single-trip-loop-peel", "simple-flattening-cleanup-unflattener"}:
        allowed = {"enable_dead_store_elimination"} if pass_id == "simple-flattening-cleanup-unflattener" else set()
        unknown = sorted(set(rule.options).difference(allowed))
        if unknown:
            raise _error_for_rule(rule, "option has no typed equivalent", field=f"config.{unknown[0]}")
        return dict(rule.options)
    return dict(rule.options)


_BLOCK_RULE_TO_PASS = {
    "ForwardConstantPropagationRule": "forward-constant-propagation",
    "IdentityCallResolver": "identity-call-resolver",
    "IndirectBranchResolver": "indirect-branch-resolver",
    "IndirectCallResolver": "indirect-call-resolver",
    "MbaStatePreconditioner": "mba-state-preconditioner",
    "SingleTripLoopPeel": "single-trip-loop-peel",
    "SimpleFlatteningCleanupUnflattener": "simple-flattening-cleanup-unflattener",
}


def _validate_cross_section_ownership(
    rules: Sequence[LegacyRule],
) -> None:
    """Reject wrong-section rules and every duplicate typed owner up front."""

    transform_map = _mba_transform_map()
    block_owned_names = frozenset(
        {_STATE_RULE_NAME, _JUMP_RULE_NAME, *_BLOCK_RULE_TO_PASS}
    )
    owners: dict[tuple[str, str], LegacyRule] = {}
    for rule in rules:
        name = rule.name
        if rule.section == "ins_rules":
            if name in block_owned_names:
                raise _error_for_rule(rule, "block-owned rule must be in blk_rules", field="name")
            transform_id = transform_map.get(name)
            if transform_id is not None:
                owner_key = ("mba-transform", transform_id)
            elif name in _CONSTANT_RULE_NAMES:
                owner_key = ("constant-rule", name)
            else:
                # Unknown instruction names retain their precise unknown-rule
                # diagnostic in ``_project_mba_rules``.
                continue
        else:
            if name in transform_map:
                raise _error_for_rule(rule, "instruction rule must be in ins_rules", field="name")
            if name in _CONSTANT_INSTRUCTION_RULE_NAMES:
                raise _error_for_rule(rule, "instruction rule must be in ins_rules", field="name")
            if name in _CONSTANT_RULE_NAMES:
                owner_key = ("constant-rule", name)
            elif name == _STATE_RULE_NAME:
                owner_key = ("pass", "state-machine")
            elif name == _JUMP_RULE_NAME:
                owner_key = ("pass", "jump-fixer")
            else:
                pass_id = _BLOCK_RULE_TO_PASS.get(name)
                if pass_id is None:
                    # Unknown block names retain their precise unknown-rule
                    # diagnostic in ``_project_block_rules``.
                    continue
                owner_key = ("pass", pass_id)
        previous = owners.get(owner_key)
        if previous is not None:
            raise _error_for_rule(
                rule,
                f"conflicting duplicate ownership with "
                f"{previous.section}[{previous.index}]",
                field="name",
            )
        owners[owner_key] = rule


def _project_block_rules(
    rules: Sequence[LegacyRule], *, known: bool = False, bundled_constant: bool = False
) -> list[tuple[dict[str, object], LegacyRule]]:
    entries: list[tuple[dict[str, object], LegacyRule]] = []
    owners: dict[str, LegacyRule] = {}
    for rule in rules:
        name = rule.name
        if name in _CONSTANT_RULE_NAMES:
            if name == "ForwardConstantPropagationRule" and bundled_constant:
                continue
            if name in _CONSTANT_INSTRUCTION_RULE_NAMES:
                raise _error_for_rule(rule, "instruction rule is in blk_rules", field="name")
            continue
        if name == _STATE_RULE_NAME:
            pass_ids = _STATE_MACHINE_PASS_IDS
            options = _state_options(rule) if not known else _state_options(rule)
        elif name == _JUMP_RULE_NAME:
            pass_ids = ("jump-fixer",)
            options = _jump_options(rule) if not known else _jump_options(rule)
        else:
            pass_id = _BLOCK_RULE_TO_PASS.get(name)
            if pass_id is None:
                # Instruction transforms appearing in blk_rules are not a
                # valid current owner, but unknown names must still be named.
                if name in _mba_transform_map():
                    raise _error_for_rule(rule, "instruction rule is in blk_rules", field="name")
                raise _error_for_rule(rule, "unknown block rule", field="name")
            pass_ids = (pass_id,)
            options = _direct_options(rule, pass_id)
        for pass_id in pass_ids:
            if pass_id in owners and not known:
                raise _error_for_rule(rule, "conflicting duplicate ownership", field="name")
            owners[pass_id] = rule
            entries.append(
                ({"pass_id": pass_id, "options": copy.deepcopy(options)}, rule)
            )
    return entries


def _config_entry(
    pass_id: str,
    options: Mapping[str, object],
    *,
    owners: Sequence[LegacyRule] = (),
) -> dict[str, object]:
    config = PipelineConfig(pass_id=pass_id, options=dict(options))
    # Typed validation is intentionally performed before serialization.  This
    # catches unknown pass IDs, malformed fields, and editor-invisible values.
    try:
        validated = _validate_v2_entries((config.to_dict(),), path_prefix="pipeline_v2")
    except LegacyMigrationError as exc:
        if owners:
            raise _typed_error_for_rules(owners, str(exc)) from exc
        raise
    return validated[0]


def _validate_project_pipeline(entries: Sequence[Mapping[str, object]]) -> tuple[dict[str, object], ...]:
    return _validate_v2_entries(entries, path_prefix="additional_configuration.pipeline_v2")


def _known_projection(
    legacy: LegacyProject, portfolio: KnownPortfolio
) -> dict[str, object]:
    # The donor name is retained in ``KnownPortfolio`` as historical evidence;
    # migration uses the checked-in full template even after donor files are
    # deleted by the cutover.
    try:
        template = _KNOWN_DONOR_TEMPLATES[legacy.source_name]
    except KeyError as exc:
        raise LegacyMigrationError(
            f"missing checked-in donor template for {legacy.source_name}"
        ) from exc
    entries = _validate_v2_entries(
        template["pipeline_v2"],
        path_prefix="known donor pipeline_v2",
        normalize=False,
    )
    additional = _owned_additional(template, pipeline=entries)
    return {
        "description": _normalize_description(legacy.description, legacy.source_name),
        "additional_configuration": additional,
    }


def _generic_projection(legacy: LegacyProject) -> dict[str, object]:
    # Keep the bundle/section conditionals explicit: constant ownership spans
    # both legacy sections, while every other adapter has one source section.
    # A flat rule table would obscure those fail-closed ownership boundaries.
    _validate_cross_section_ownership(legacy.active_rules)
    ins_rules = tuple(rule for rule in legacy.active_rules if rule.section == "ins_rules")
    blk_rules = tuple(rule for rule in legacy.active_rules if rule.section == "blk_rules")
    all_names = {rule.name for rule in legacy.active_rules}
    constant_names = all_names.intersection(_CONSTANT_RULE_NAMES)
    complete_bundle = _CONSTANT_RULE_NAMES.issubset(all_names)
    if constant_names and not complete_bundle:
        owner = next(rule for rule in legacy.active_rules if rule.name in _CONSTANT_RULE_NAMES)
        raise _error_for_rule(owner, "partial constant-simplification owner bundle", field="name")

    entries: list[dict[str, object]] = []
    if complete_bundle:
        constant_rules = tuple(rule for rule in legacy.active_rules if rule.name in _CONSTANT_RULE_NAMES)
        entries.append(
            _config_entry(
                "constant-simplification",
                _constant_options(constant_rules),
                owners=constant_rules,
            )
        )
    instruction_rules = tuple(rule for rule in ins_rules if rule.name not in _CONSTANT_INSTRUCTION_RULE_NAMES)
    mba_options = _project_mba_rules(instruction_rules)
    if mba_options is not None:
        entries.append(_config_entry("mba-simplify", mba_options, owners=instruction_rules))
    block_rules = tuple(rule for rule in blk_rules if not (rule.name == "ForwardConstantPropagationRule" and complete_bundle))
    for entry, owner in _project_block_rules(block_rules, bundled_constant=complete_bundle):
        entries.append(
            _config_entry(
                str(entry["pass_id"]), entry.get("options", {}), owners=(owner,)
            )
        )
    if not entries:
        raise LegacyMigrationError("migration produced an empty pipeline_v2")
    return _canonical_document(legacy, _validate_project_pipeline(entries))


def _normalize_v2(legacy: LegacyProject, payload: object) -> dict[str, object]:
    entries = _validate_v2_entries(payload, path_prefix="additional_configuration.pipeline_v2")
    return _canonical_document(legacy, entries)


def migrate_legacy_document(
    document: Mapping[str, object], *, source_name: str
) -> dict[str, object]:
    """Convert one legacy or already-v2 project document to canonical v2.

    The function is deterministic and performs no filesystem writes.  Known
    bundled documents use an exact fingerprinted donor projection; all other
    legacy documents are converted through strict current typed ownership.
    """

    legacy = _parse_legacy_document(document, source_name=source_name)
    payload = _pipeline_payload(legacy)
    active_legacy = legacy.active_rules
    mode = legacy.additional_configuration.get("pipeline_v2_mode", _MISSING)
    if mode is not _MISSING and mode != "config-v2":
        raise LegacyMigrationError(
            "additional_configuration.pipeline_v2_mode must be 'config-v2'"
        )
    if payload is not _MISSING:
        if active_legacy:
            raise LegacyMigrationError("mixed v2 and active legacy configuration")
        return _normalize_v2(legacy, payload)

    portfolio = _KNOWN_BY_IDENTITY.get((legacy.source_name, legacy.canonical_fingerprint))
    if portfolio is not None:
        result = _known_projection(legacy, portfolio)
        _validate_v2_entries(
            result["additional_configuration"]["pipeline_v2"],
            path_prefix="additional_configuration.pipeline_v2",
        )
        return result
    return _generic_projection(legacy)


def is_canonical_v2_document(document: Mapping[str, object]) -> bool:
    """Return whether a document is already normalized canonical config-v2."""

    try:
        legacy = _parse_legacy_document(document, source_name="canonical.json")
        if legacy.active_rules:
            return False
        payload = _pipeline_payload(legacy)
        if payload is _MISSING:
            return False
        additional = legacy.additional_configuration
        if "pipeline_v2_mode" in additional or "config_v2_canary" in additional:
            return False
        _validate_v2_entries(payload, path_prefix="additional_configuration.pipeline_v2")
        _owned_additional(additional, pipeline=())
        return True
    except (LegacyMigrationError, TypeError, ValueError, RuntimeError):
        return False


__all__ = [
    "KnownPortfolio",
    "LegacyMigrationError",
    "LegacyProject",
    "LegacyRule",
    "is_canonical_v2_document",
    "migrate_legacy_document",
]
