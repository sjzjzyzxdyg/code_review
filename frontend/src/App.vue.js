import { computed, onMounted, ref } from "vue";
import { CloudUploadOutlined, FileSearchOutlined, PlayCircleOutlined, ReloadOutlined } from "@ant-design/icons-vue";
import { createTask, listIssues, listProjects, listReports, listTasks, runTask, uploadProject } from "./api";
const loading = ref(false);
const selectedProjectId = ref();
const selectedTaskId = ref();
const scanScope = ref(".");
const enableCppcheck = ref(true);
const enableClang = ref(false);
const cppcheckLevel = ref("all");
const projects = ref([]);
const tasks = ref([]);
const issues = ref([]);
const reports = ref([]);
const activeIssue = ref();
const activeCallNodes = computed(() => activeIssue.value?.call_chain_graph?.nodes ?? []);
const activeCallEdges = computed(() => activeIssue.value?.call_chain_graph?.edges ?? []);
const activeAstTypes = computed(() => activeIssue.value?.ast_context?.types ?? []);
const projectOptions = computed(() => projects.value.map((project) => ({ label: project.name, value: project.id })));
const taskOptions = computed(() => tasks.value.map((task) => ({
    label: `${task.id.slice(0, 8)} - ${task.status}`,
    value: task.id
})));
const riskColor = {
    critical: "red",
    high: "volcano",
    medium: "gold",
    low: "green"
};
function colorForRisk(risk) {
    return riskColor[risk];
}
const issueColumns = [
    { title: "Risk", dataIndex: "risk_level", key: "risk_level", width: 96 },
    { title: "Type", dataIndex: "issue_type", key: "issue_type" },
    { title: "Location", key: "location" },
    { title: "Tool", dataIndex: "tool", key: "tool", width: 130 },
    { title: "Confidence", dataIndex: "confidence", key: "confidence", width: 120 }
];
async function refreshAll() {
    loading.value = true;
    try {
        projects.value = await listProjects();
        tasks.value = await listTasks();
        if (!selectedProjectId.value && projects.value[0]) {
            selectedProjectId.value = projects.value[0].id;
        }
        if (!selectedTaskId.value && tasks.value[0]) {
            selectedTaskId.value = tasks.value[0].id;
        }
        await refreshTaskData();
    }
    finally {
        loading.value = false;
    }
}
async function refreshTaskData() {
    issues.value = await listIssues(selectedTaskId.value);
    reports.value = await listReports(selectedTaskId.value);
    activeIssue.value = issues.value[0];
}
const uploadProps = {
    accept: ".zip",
    maxCount: 1,
    showUploadList: false,
    customRequest: async ({ file, onSuccess, onError }) => {
        try {
            const project = await uploadProject(file);
            projects.value = await listProjects();
            selectedProjectId.value = project.id;
            onSuccess?.(project);
        }
        catch (error) {
            onError?.(error);
        }
    }
};
async function onUploadChange(info) {
    if (info.file.status === "done") {
        await refreshAll();
    }
}
async function submitTask(autoStart = true) {
    if (!selectedProjectId.value) {
        return;
    }
    loading.value = true;
    try {
        const task = await createTask({
            project_id: selectedProjectId.value,
            scan_scope: scanScope.value,
            auto_start: autoStart,
            rule_config: {
                cppcheck: enableCppcheck.value,
                clang: enableClang.value,
                cppcheck_enable: cppcheckLevel.value
            }
        });
        selectedTaskId.value = task.id;
        await refreshAll();
    }
    finally {
        loading.value = false;
    }
}
async function rerunSelectedTask() {
    if (!selectedTaskId.value) {
        return;
    }
    loading.value = true;
    try {
        await runTask(selectedTaskId.value);
        await refreshAll();
    }
    finally {
        loading.value = false;
    }
}
onMounted(refreshAll);
debugger; /* PartiallyEnd: #3632/scriptSetup.vue */
const __VLS_ctx = {};
let __VLS_components;
let __VLS_directives;
const __VLS_0 = {}.ALayout;
/** @type {[typeof __VLS_components.ALayout, typeof __VLS_components.aLayout, typeof __VLS_components.ALayout, typeof __VLS_components.aLayout, ]} */ ;
// @ts-ignore
const __VLS_1 = __VLS_asFunctionalComponent(__VLS_0, new __VLS_0({
    ...{ class: "app-shell" },
}));
const __VLS_2 = __VLS_1({
    ...{ class: "app-shell" },
}, ...__VLS_functionalComponentArgsRest(__VLS_1));
var __VLS_4 = {};
__VLS_3.slots.default;
const __VLS_5 = {}.ALayoutSider;
/** @type {[typeof __VLS_components.ALayoutSider, typeof __VLS_components.aLayoutSider, typeof __VLS_components.ALayoutSider, typeof __VLS_components.aLayoutSider, ]} */ ;
// @ts-ignore
const __VLS_6 = __VLS_asFunctionalComponent(__VLS_5, new __VLS_5({
    ...{ class: "side" },
    width: "260",
}));
const __VLS_7 = __VLS_6({
    ...{ class: "side" },
    width: "260",
}, ...__VLS_functionalComponentArgsRest(__VLS_6));
__VLS_8.slots.default;
__VLS_asFunctionalElement(__VLS_intrinsicElements.div, __VLS_intrinsicElements.div)({
    ...{ class: "brand" },
});
const __VLS_9 = {}.FileSearchOutlined;
/** @type {[typeof __VLS_components.FileSearchOutlined, ]} */ ;
// @ts-ignore
const __VLS_10 = __VLS_asFunctionalComponent(__VLS_9, new __VLS_9({}));
const __VLS_11 = __VLS_10({}, ...__VLS_functionalComponentArgsRest(__VLS_10));
__VLS_asFunctionalElement(__VLS_intrinsicElements.span, __VLS_intrinsicElements.span)({});
const __VLS_13 = {}.ASpace;
/** @type {[typeof __VLS_components.ASpace, typeof __VLS_components.aSpace, typeof __VLS_components.ASpace, typeof __VLS_components.aSpace, ]} */ ;
// @ts-ignore
const __VLS_14 = __VLS_asFunctionalComponent(__VLS_13, new __VLS_13({
    direction: "vertical",
    ...{ class: "side-stack" },
    size: (16),
}));
const __VLS_15 = __VLS_14({
    direction: "vertical",
    ...{ class: "side-stack" },
    size: (16),
}, ...__VLS_functionalComponentArgsRest(__VLS_14));
__VLS_16.slots.default;
__VLS_asFunctionalElement(__VLS_intrinsicElements.section, __VLS_intrinsicElements.section)({});
__VLS_asFunctionalElement(__VLS_intrinsicElements.h2, __VLS_intrinsicElements.h2)({});
const __VLS_17 = {}.AUpload;
/** @type {[typeof __VLS_components.AUpload, typeof __VLS_components.aUpload, typeof __VLS_components.AUpload, typeof __VLS_components.aUpload, ]} */ ;
// @ts-ignore
const __VLS_18 = __VLS_asFunctionalComponent(__VLS_17, new __VLS_17({
    ...{ 'onChange': {} },
    ...(__VLS_ctx.uploadProps),
}));
const __VLS_19 = __VLS_18({
    ...{ 'onChange': {} },
    ...(__VLS_ctx.uploadProps),
}, ...__VLS_functionalComponentArgsRest(__VLS_18));
let __VLS_21;
let __VLS_22;
let __VLS_23;
const __VLS_24 = {
    onChange: (__VLS_ctx.onUploadChange)
};
__VLS_20.slots.default;
const __VLS_25 = {}.AButton;
/** @type {[typeof __VLS_components.AButton, typeof __VLS_components.aButton, typeof __VLS_components.AButton, typeof __VLS_components.aButton, ]} */ ;
// @ts-ignore
const __VLS_26 = __VLS_asFunctionalComponent(__VLS_25, new __VLS_25({
    block: true,
}));
const __VLS_27 = __VLS_26({
    block: true,
}, ...__VLS_functionalComponentArgsRest(__VLS_26));
__VLS_28.slots.default;
const __VLS_29 = {}.CloudUploadOutlined;
/** @type {[typeof __VLS_components.CloudUploadOutlined, ]} */ ;
// @ts-ignore
const __VLS_30 = __VLS_asFunctionalComponent(__VLS_29, new __VLS_29({}));
const __VLS_31 = __VLS_30({}, ...__VLS_functionalComponentArgsRest(__VLS_30));
var __VLS_28;
var __VLS_20;
const __VLS_33 = {}.ASelect;
/** @type {[typeof __VLS_components.ASelect, typeof __VLS_components.aSelect, ]} */ ;
// @ts-ignore
const __VLS_34 = __VLS_asFunctionalComponent(__VLS_33, new __VLS_33({
    value: (__VLS_ctx.selectedProjectId),
    ...{ class: "full" },
    options: (__VLS_ctx.projectOptions),
    placeholder: "Select project",
}));
const __VLS_35 = __VLS_34({
    value: (__VLS_ctx.selectedProjectId),
    ...{ class: "full" },
    options: (__VLS_ctx.projectOptions),
    placeholder: "Select project",
}, ...__VLS_functionalComponentArgsRest(__VLS_34));
__VLS_asFunctionalElement(__VLS_intrinsicElements.section, __VLS_intrinsicElements.section)({});
__VLS_asFunctionalElement(__VLS_intrinsicElements.h2, __VLS_intrinsicElements.h2)({});
const __VLS_37 = {}.ACheckbox;
/** @type {[typeof __VLS_components.ACheckbox, typeof __VLS_components.aCheckbox, typeof __VLS_components.ACheckbox, typeof __VLS_components.aCheckbox, ]} */ ;
// @ts-ignore
const __VLS_38 = __VLS_asFunctionalComponent(__VLS_37, new __VLS_37({
    checked: (__VLS_ctx.enableCppcheck),
}));
const __VLS_39 = __VLS_38({
    checked: (__VLS_ctx.enableCppcheck),
}, ...__VLS_functionalComponentArgsRest(__VLS_38));
__VLS_40.slots.default;
var __VLS_40;
const __VLS_41 = {}.ACheckbox;
/** @type {[typeof __VLS_components.ACheckbox, typeof __VLS_components.aCheckbox, typeof __VLS_components.ACheckbox, typeof __VLS_components.aCheckbox, ]} */ ;
// @ts-ignore
const __VLS_42 = __VLS_asFunctionalComponent(__VLS_41, new __VLS_41({
    checked: (__VLS_ctx.enableClang),
}));
const __VLS_43 = __VLS_42({
    checked: (__VLS_ctx.enableClang),
}, ...__VLS_functionalComponentArgsRest(__VLS_42));
__VLS_44.slots.default;
var __VLS_44;
const __VLS_45 = {}.ASelect;
/** @type {[typeof __VLS_components.ASelect, typeof __VLS_components.aSelect, typeof __VLS_components.ASelect, typeof __VLS_components.aSelect, ]} */ ;
// @ts-ignore
const __VLS_46 = __VLS_asFunctionalComponent(__VLS_45, new __VLS_45({
    value: (__VLS_ctx.cppcheckLevel),
    ...{ class: "full" },
}));
const __VLS_47 = __VLS_46({
    value: (__VLS_ctx.cppcheckLevel),
    ...{ class: "full" },
}, ...__VLS_functionalComponentArgsRest(__VLS_46));
__VLS_48.slots.default;
const __VLS_49 = {}.ASelectOption;
/** @type {[typeof __VLS_components.ASelectOption, typeof __VLS_components.aSelectOption, typeof __VLS_components.ASelectOption, typeof __VLS_components.aSelectOption, ]} */ ;
// @ts-ignore
const __VLS_50 = __VLS_asFunctionalComponent(__VLS_49, new __VLS_49({
    value: "all",
}));
const __VLS_51 = __VLS_50({
    value: "all",
}, ...__VLS_functionalComponentArgsRest(__VLS_50));
__VLS_52.slots.default;
var __VLS_52;
const __VLS_53 = {}.ASelectOption;
/** @type {[typeof __VLS_components.ASelectOption, typeof __VLS_components.aSelectOption, typeof __VLS_components.ASelectOption, typeof __VLS_components.aSelectOption, ]} */ ;
// @ts-ignore
const __VLS_54 = __VLS_asFunctionalComponent(__VLS_53, new __VLS_53({
    value: "warning",
}));
const __VLS_55 = __VLS_54({
    value: "warning",
}, ...__VLS_functionalComponentArgsRest(__VLS_54));
__VLS_56.slots.default;
var __VLS_56;
const __VLS_57 = {}.ASelectOption;
/** @type {[typeof __VLS_components.ASelectOption, typeof __VLS_components.aSelectOption, typeof __VLS_components.ASelectOption, typeof __VLS_components.aSelectOption, ]} */ ;
// @ts-ignore
const __VLS_58 = __VLS_asFunctionalComponent(__VLS_57, new __VLS_57({
    value: "style",
}));
const __VLS_59 = __VLS_58({
    value: "style",
}, ...__VLS_functionalComponentArgsRest(__VLS_58));
__VLS_60.slots.default;
var __VLS_60;
const __VLS_61 = {}.ASelectOption;
/** @type {[typeof __VLS_components.ASelectOption, typeof __VLS_components.aSelectOption, typeof __VLS_components.ASelectOption, typeof __VLS_components.aSelectOption, ]} */ ;
// @ts-ignore
const __VLS_62 = __VLS_asFunctionalComponent(__VLS_61, new __VLS_61({
    value: "performance",
}));
const __VLS_63 = __VLS_62({
    value: "performance",
}, ...__VLS_functionalComponentArgsRest(__VLS_62));
__VLS_64.slots.default;
var __VLS_64;
var __VLS_48;
const __VLS_65 = {}.AInput;
/** @type {[typeof __VLS_components.AInput, typeof __VLS_components.aInput, ]} */ ;
// @ts-ignore
const __VLS_66 = __VLS_asFunctionalComponent(__VLS_65, new __VLS_65({
    value: (__VLS_ctx.scanScope),
    addonBefore: "Scope",
}));
const __VLS_67 = __VLS_66({
    value: (__VLS_ctx.scanScope),
    addonBefore: "Scope",
}, ...__VLS_functionalComponentArgsRest(__VLS_66));
const __VLS_69 = {}.AButton;
/** @type {[typeof __VLS_components.AButton, typeof __VLS_components.aButton, typeof __VLS_components.AButton, typeof __VLS_components.aButton, ]} */ ;
// @ts-ignore
const __VLS_70 = __VLS_asFunctionalComponent(__VLS_69, new __VLS_69({
    ...{ 'onClick': {} },
    type: "primary",
    block: true,
}));
const __VLS_71 = __VLS_70({
    ...{ 'onClick': {} },
    type: "primary",
    block: true,
}, ...__VLS_functionalComponentArgsRest(__VLS_70));
let __VLS_73;
let __VLS_74;
let __VLS_75;
const __VLS_76 = {
    onClick: (...[$event]) => {
        __VLS_ctx.submitTask(true);
    }
};
__VLS_72.slots.default;
const __VLS_77 = {}.PlayCircleOutlined;
/** @type {[typeof __VLS_components.PlayCircleOutlined, ]} */ ;
// @ts-ignore
const __VLS_78 = __VLS_asFunctionalComponent(__VLS_77, new __VLS_77({}));
const __VLS_79 = __VLS_78({}, ...__VLS_functionalComponentArgsRest(__VLS_78));
var __VLS_72;
__VLS_asFunctionalElement(__VLS_intrinsicElements.section, __VLS_intrinsicElements.section)({});
__VLS_asFunctionalElement(__VLS_intrinsicElements.h2, __VLS_intrinsicElements.h2)({});
const __VLS_81 = {}.ASelect;
/** @type {[typeof __VLS_components.ASelect, typeof __VLS_components.aSelect, ]} */ ;
// @ts-ignore
const __VLS_82 = __VLS_asFunctionalComponent(__VLS_81, new __VLS_81({
    ...{ 'onChange': {} },
    value: (__VLS_ctx.selectedTaskId),
    ...{ class: "full" },
    options: (__VLS_ctx.taskOptions),
    placeholder: "Select task",
}));
const __VLS_83 = __VLS_82({
    ...{ 'onChange': {} },
    value: (__VLS_ctx.selectedTaskId),
    ...{ class: "full" },
    options: (__VLS_ctx.taskOptions),
    placeholder: "Select task",
}, ...__VLS_functionalComponentArgsRest(__VLS_82));
let __VLS_85;
let __VLS_86;
let __VLS_87;
const __VLS_88 = {
    onChange: (__VLS_ctx.refreshTaskData)
};
var __VLS_84;
const __VLS_89 = {}.AButton;
/** @type {[typeof __VLS_components.AButton, typeof __VLS_components.aButton, typeof __VLS_components.AButton, typeof __VLS_components.aButton, ]} */ ;
// @ts-ignore
const __VLS_90 = __VLS_asFunctionalComponent(__VLS_89, new __VLS_89({
    ...{ 'onClick': {} },
    block: true,
}));
const __VLS_91 = __VLS_90({
    ...{ 'onClick': {} },
    block: true,
}, ...__VLS_functionalComponentArgsRest(__VLS_90));
let __VLS_93;
let __VLS_94;
let __VLS_95;
const __VLS_96 = {
    onClick: (__VLS_ctx.rerunSelectedTask)
};
__VLS_92.slots.default;
const __VLS_97 = {}.ReloadOutlined;
/** @type {[typeof __VLS_components.ReloadOutlined, ]} */ ;
// @ts-ignore
const __VLS_98 = __VLS_asFunctionalComponent(__VLS_97, new __VLS_97({}));
const __VLS_99 = __VLS_98({}, ...__VLS_functionalComponentArgsRest(__VLS_98));
var __VLS_92;
var __VLS_16;
var __VLS_8;
const __VLS_101 = {}.ALayoutContent;
/** @type {[typeof __VLS_components.ALayoutContent, typeof __VLS_components.aLayoutContent, typeof __VLS_components.ALayoutContent, typeof __VLS_components.aLayoutContent, ]} */ ;
// @ts-ignore
const __VLS_102 = __VLS_asFunctionalComponent(__VLS_101, new __VLS_101({
    ...{ class: "workspace" },
}));
const __VLS_103 = __VLS_102({
    ...{ class: "workspace" },
}, ...__VLS_functionalComponentArgsRest(__VLS_102));
__VLS_104.slots.default;
__VLS_asFunctionalElement(__VLS_intrinsicElements.header, __VLS_intrinsicElements.header)({
    ...{ class: "topbar" },
});
__VLS_asFunctionalElement(__VLS_intrinsicElements.div, __VLS_intrinsicElements.div)({});
__VLS_asFunctionalElement(__VLS_intrinsicElements.h1, __VLS_intrinsicElements.h1)({});
__VLS_asFunctionalElement(__VLS_intrinsicElements.p, __VLS_intrinsicElements.p)({});
(__VLS_ctx.issues.length);
(__VLS_ctx.reports.length);
const __VLS_105 = {}.AButton;
/** @type {[typeof __VLS_components.AButton, typeof __VLS_components.aButton, typeof __VLS_components.AButton, typeof __VLS_components.aButton, ]} */ ;
// @ts-ignore
const __VLS_106 = __VLS_asFunctionalComponent(__VLS_105, new __VLS_105({
    ...{ 'onClick': {} },
    loading: (__VLS_ctx.loading),
}));
const __VLS_107 = __VLS_106({
    ...{ 'onClick': {} },
    loading: (__VLS_ctx.loading),
}, ...__VLS_functionalComponentArgsRest(__VLS_106));
let __VLS_109;
let __VLS_110;
let __VLS_111;
const __VLS_112 = {
    onClick: (__VLS_ctx.refreshAll)
};
__VLS_108.slots.default;
const __VLS_113 = {}.ReloadOutlined;
/** @type {[typeof __VLS_components.ReloadOutlined, ]} */ ;
// @ts-ignore
const __VLS_114 = __VLS_asFunctionalComponent(__VLS_113, new __VLS_113({}));
const __VLS_115 = __VLS_114({}, ...__VLS_functionalComponentArgsRest(__VLS_114));
var __VLS_108;
const __VLS_117 = {}.ATabs;
/** @type {[typeof __VLS_components.ATabs, typeof __VLS_components.aTabs, typeof __VLS_components.ATabs, typeof __VLS_components.aTabs, ]} */ ;
// @ts-ignore
const __VLS_118 = __VLS_asFunctionalComponent(__VLS_117, new __VLS_117({}));
const __VLS_119 = __VLS_118({}, ...__VLS_functionalComponentArgsRest(__VLS_118));
__VLS_120.slots.default;
const __VLS_121 = {}.ATabPane;
/** @type {[typeof __VLS_components.ATabPane, typeof __VLS_components.aTabPane, typeof __VLS_components.ATabPane, typeof __VLS_components.aTabPane, ]} */ ;
// @ts-ignore
const __VLS_122 = __VLS_asFunctionalComponent(__VLS_121, new __VLS_121({
    key: "issues",
    tab: "Issues",
}));
const __VLS_123 = __VLS_122({
    key: "issues",
    tab: "Issues",
}, ...__VLS_functionalComponentArgsRest(__VLS_122));
__VLS_124.slots.default;
__VLS_asFunctionalElement(__VLS_intrinsicElements.div, __VLS_intrinsicElements.div)({
    ...{ class: "content-grid" },
});
__VLS_asFunctionalElement(__VLS_intrinsicElements.section, __VLS_intrinsicElements.section)({
    ...{ class: "table-panel" },
});
const __VLS_125 = {}.ATable;
/** @type {[typeof __VLS_components.ATable, typeof __VLS_components.aTable, typeof __VLS_components.ATable, typeof __VLS_components.aTable, ]} */ ;
// @ts-ignore
const __VLS_126 = __VLS_asFunctionalComponent(__VLS_125, new __VLS_125({
    ...{ 'onRow': {} },
    columns: (__VLS_ctx.issueColumns),
    dataSource: (__VLS_ctx.issues),
    rowKey: ((record) => record.id),
    pagination: ({ pageSize: 8 }),
    size: "middle",
}));
const __VLS_127 = __VLS_126({
    ...{ 'onRow': {} },
    columns: (__VLS_ctx.issueColumns),
    dataSource: (__VLS_ctx.issues),
    rowKey: ((record) => record.id),
    pagination: ({ pageSize: 8 }),
    size: "middle",
}, ...__VLS_functionalComponentArgsRest(__VLS_126));
let __VLS_129;
let __VLS_130;
let __VLS_131;
const __VLS_132 = {
    onRow: ((record) => ({ onClick: () => (__VLS_ctx.activeIssue = record) }))
};
__VLS_128.slots.default;
{
    const { bodyCell: __VLS_thisSlot } = __VLS_128.slots;
    const [{ column, record }] = __VLS_getSlotParams(__VLS_thisSlot);
    if (column.key === 'risk_level') {
        const __VLS_133 = {}.ATag;
        /** @type {[typeof __VLS_components.ATag, typeof __VLS_components.aTag, typeof __VLS_components.ATag, typeof __VLS_components.aTag, ]} */ ;
        // @ts-ignore
        const __VLS_134 = __VLS_asFunctionalComponent(__VLS_133, new __VLS_133({
            color: (__VLS_ctx.colorForRisk(record.risk_level)),
        }));
        const __VLS_135 = __VLS_134({
            color: (__VLS_ctx.colorForRisk(record.risk_level)),
        }, ...__VLS_functionalComponentArgsRest(__VLS_134));
        __VLS_136.slots.default;
        (record.risk_level);
        var __VLS_136;
    }
    if (column.key === 'location') {
        __VLS_asFunctionalElement(__VLS_intrinsicElements.span, __VLS_intrinsicElements.span)({});
        (record.file_path);
        (record.line);
    }
    if (column.key === 'confidence') {
        const __VLS_137 = {}.AProgress;
        /** @type {[typeof __VLS_components.AProgress, typeof __VLS_components.aProgress, ]} */ ;
        // @ts-ignore
        const __VLS_138 = __VLS_asFunctionalComponent(__VLS_137, new __VLS_137({
            percent: (Math.round(record.confidence * 100)),
            size: "small",
            showInfo: (false),
        }));
        const __VLS_139 = __VLS_138({
            percent: (Math.round(record.confidence * 100)),
            size: "small",
            showInfo: (false),
        }, ...__VLS_functionalComponentArgsRest(__VLS_138));
    }
}
var __VLS_128;
if (__VLS_ctx.activeIssue) {
    __VLS_asFunctionalElement(__VLS_intrinsicElements.aside, __VLS_intrinsicElements.aside)({
        ...{ class: "detail-panel" },
    });
    __VLS_asFunctionalElement(__VLS_intrinsicElements.h2, __VLS_intrinsicElements.h2)({});
    (__VLS_ctx.activeIssue.issue_type);
    const __VLS_141 = {}.ADescriptions;
    /** @type {[typeof __VLS_components.ADescriptions, typeof __VLS_components.aDescriptions, typeof __VLS_components.ADescriptions, typeof __VLS_components.aDescriptions, ]} */ ;
    // @ts-ignore
    const __VLS_142 = __VLS_asFunctionalComponent(__VLS_141, new __VLS_141({
        size: "small",
        column: (1),
        bordered: true,
    }));
    const __VLS_143 = __VLS_142({
        size: "small",
        column: (1),
        bordered: true,
    }, ...__VLS_functionalComponentArgsRest(__VLS_142));
    __VLS_144.slots.default;
    const __VLS_145 = {}.ADescriptionsItem;
    /** @type {[typeof __VLS_components.ADescriptionsItem, typeof __VLS_components.aDescriptionsItem, typeof __VLS_components.ADescriptionsItem, typeof __VLS_components.aDescriptionsItem, ]} */ ;
    // @ts-ignore
    const __VLS_146 = __VLS_asFunctionalComponent(__VLS_145, new __VLS_145({
        label: "Location",
    }));
    const __VLS_147 = __VLS_146({
        label: "Location",
    }, ...__VLS_functionalComponentArgsRest(__VLS_146));
    __VLS_148.slots.default;
    (__VLS_ctx.activeIssue.file_path);
    (__VLS_ctx.activeIssue.line);
    var __VLS_148;
    const __VLS_149 = {}.ADescriptionsItem;
    /** @type {[typeof __VLS_components.ADescriptionsItem, typeof __VLS_components.aDescriptionsItem, typeof __VLS_components.ADescriptionsItem, typeof __VLS_components.aDescriptionsItem, ]} */ ;
    // @ts-ignore
    const __VLS_150 = __VLS_asFunctionalComponent(__VLS_149, new __VLS_149({
        label: "Reason",
    }));
    const __VLS_151 = __VLS_150({
        label: "Reason",
    }, ...__VLS_functionalComponentArgsRest(__VLS_150));
    __VLS_152.slots.default;
    (__VLS_ctx.activeIssue.reason);
    var __VLS_152;
    const __VLS_153 = {}.ADescriptionsItem;
    /** @type {[typeof __VLS_components.ADescriptionsItem, typeof __VLS_components.aDescriptionsItem, typeof __VLS_components.ADescriptionsItem, typeof __VLS_components.aDescriptionsItem, ]} */ ;
    // @ts-ignore
    const __VLS_154 = __VLS_asFunctionalComponent(__VLS_153, new __VLS_153({
        label: "Fix",
    }));
    const __VLS_155 = __VLS_154({
        label: "Fix",
    }, ...__VLS_functionalComponentArgsRest(__VLS_154));
    __VLS_156.slots.default;
    (__VLS_ctx.activeIssue.fix_suggestion);
    var __VLS_156;
    const __VLS_157 = {}.ADescriptionsItem;
    /** @type {[typeof __VLS_components.ADescriptionsItem, typeof __VLS_components.aDescriptionsItem, typeof __VLS_components.ADescriptionsItem, typeof __VLS_components.aDescriptionsItem, ]} */ ;
    // @ts-ignore
    const __VLS_158 = __VLS_asFunctionalComponent(__VLS_157, new __VLS_157({
        label: "AST",
    }));
    const __VLS_159 = __VLS_158({
        label: "AST",
    }, ...__VLS_functionalComponentArgsRest(__VLS_158));
    __VLS_160.slots.default;
    (__VLS_ctx.activeIssue.ast_summary || "N/A");
    var __VLS_160;
    var __VLS_144;
    __VLS_asFunctionalElement(__VLS_intrinsicElements.div, __VLS_intrinsicElements.div)({
        ...{ class: "code-block" },
    });
    __VLS_asFunctionalElement(__VLS_intrinsicElements.pre, __VLS_intrinsicElements.pre)({});
    (__VLS_ctx.activeIssue.code_snippet || "No snippet available.");
    __VLS_asFunctionalElement(__VLS_intrinsicElements.div, __VLS_intrinsicElements.div)({
        ...{ class: "ast-board" },
    });
    __VLS_asFunctionalElement(__VLS_intrinsicElements.div, __VLS_intrinsicElements.div)({
        ...{ class: "ast-item" },
    });
    __VLS_asFunctionalElement(__VLS_intrinsicElements.span, __VLS_intrinsicElements.span)({});
    __VLS_asFunctionalElement(__VLS_intrinsicElements.strong, __VLS_intrinsicElements.strong)({});
    (__VLS_ctx.activeIssue.ast_context?.function || "N/A");
    __VLS_asFunctionalElement(__VLS_intrinsicElements.div, __VLS_intrinsicElements.div)({
        ...{ class: "ast-item" },
    });
    __VLS_asFunctionalElement(__VLS_intrinsicElements.span, __VLS_intrinsicElements.span)({});
    __VLS_asFunctionalElement(__VLS_intrinsicElements.strong, __VLS_intrinsicElements.strong)({});
    (__VLS_ctx.activeAstTypes.map((item) => `${item.kind} ${item.name}`).join(", ") || "N/A");
    __VLS_asFunctionalElement(__VLS_intrinsicElements.div, __VLS_intrinsicElements.div)({
        ...{ class: "ast-item" },
    });
    __VLS_asFunctionalElement(__VLS_intrinsicElements.span, __VLS_intrinsicElements.span)({});
    __VLS_asFunctionalElement(__VLS_intrinsicElements.strong, __VLS_intrinsicElements.strong)({});
    (__VLS_ctx.activeIssue.dependencies.length);
    if (__VLS_ctx.activeCallNodes.length) {
        __VLS_asFunctionalElement(__VLS_intrinsicElements.div, __VLS_intrinsicElements.div)({
            ...{ class: "call-graph" },
        });
        __VLS_asFunctionalElement(__VLS_intrinsicElements.div, __VLS_intrinsicElements.div)({
            ...{ class: "graph-nodes" },
        });
        for (const [node] of __VLS_getVForSourceType((__VLS_ctx.activeCallNodes))) {
            __VLS_asFunctionalElement(__VLS_intrinsicElements.span, __VLS_intrinsicElements.span)({
                key: (node.id),
                ...{ class: "graph-node" },
                ...{ class: ({ active: node.in_chain }) },
            });
            (node.name);
        }
        if (__VLS_ctx.activeCallEdges.length) {
            __VLS_asFunctionalElement(__VLS_intrinsicElements.div, __VLS_intrinsicElements.div)({
                ...{ class: "graph-edges" },
            });
            for (const [edge] of __VLS_getVForSourceType((__VLS_ctx.activeCallEdges))) {
                __VLS_asFunctionalElement(__VLS_intrinsicElements.span, __VLS_intrinsicElements.span)({
                    key: (`${edge.source}-${edge.target}`),
                });
                (edge.source);
                (edge.target);
            }
        }
    }
}
var __VLS_124;
const __VLS_161 = {}.ATabPane;
/** @type {[typeof __VLS_components.ATabPane, typeof __VLS_components.aTabPane, typeof __VLS_components.ATabPane, typeof __VLS_components.aTabPane, ]} */ ;
// @ts-ignore
const __VLS_162 = __VLS_asFunctionalComponent(__VLS_161, new __VLS_161({
    key: "reports",
    tab: "Reports",
}));
const __VLS_163 = __VLS_162({
    key: "reports",
    tab: "Reports",
}, ...__VLS_functionalComponentArgsRest(__VLS_162));
__VLS_164.slots.default;
const __VLS_165 = {}.AList;
/** @type {[typeof __VLS_components.AList, typeof __VLS_components.aList, typeof __VLS_components.AList, typeof __VLS_components.aList, ]} */ ;
// @ts-ignore
const __VLS_166 = __VLS_asFunctionalComponent(__VLS_165, new __VLS_165({
    dataSource: (__VLS_ctx.reports),
    bordered: true,
}));
const __VLS_167 = __VLS_166({
    dataSource: (__VLS_ctx.reports),
    bordered: true,
}, ...__VLS_functionalComponentArgsRest(__VLS_166));
__VLS_168.slots.default;
{
    const { renderItem: __VLS_thisSlot } = __VLS_168.slots;
    const [{ item }] = __VLS_getSlotParams(__VLS_thisSlot);
    const __VLS_169 = {}.AListItem;
    /** @type {[typeof __VLS_components.AListItem, typeof __VLS_components.aListItem, typeof __VLS_components.AListItem, typeof __VLS_components.aListItem, ]} */ ;
    // @ts-ignore
    const __VLS_170 = __VLS_asFunctionalComponent(__VLS_169, new __VLS_169({}));
    const __VLS_171 = __VLS_170({}, ...__VLS_functionalComponentArgsRest(__VLS_170));
    __VLS_172.slots.default;
    const __VLS_173 = {}.AListItemMeta;
    /** @type {[typeof __VLS_components.AListItemMeta, typeof __VLS_components.aListItemMeta, ]} */ ;
    // @ts-ignore
    const __VLS_174 = __VLS_asFunctionalComponent(__VLS_173, new __VLS_173({
        title: (item.summary),
        description: (item.created_at),
    }));
    const __VLS_175 = __VLS_174({
        title: (item.summary),
        description: (item.created_at),
    }, ...__VLS_functionalComponentArgsRest(__VLS_174));
    const __VLS_177 = {}.ASpace;
    /** @type {[typeof __VLS_components.ASpace, typeof __VLS_components.aSpace, typeof __VLS_components.ASpace, typeof __VLS_components.aSpace, ]} */ ;
    // @ts-ignore
    const __VLS_178 = __VLS_asFunctionalComponent(__VLS_177, new __VLS_177({}));
    const __VLS_179 = __VLS_178({}, ...__VLS_functionalComponentArgsRest(__VLS_178));
    __VLS_180.slots.default;
    if (item.markdown_path) {
        const __VLS_181 = {}.ATag;
        /** @type {[typeof __VLS_components.ATag, typeof __VLS_components.aTag, typeof __VLS_components.ATag, typeof __VLS_components.aTag, ]} */ ;
        // @ts-ignore
        const __VLS_182 = __VLS_asFunctionalComponent(__VLS_181, new __VLS_181({}));
        const __VLS_183 = __VLS_182({}, ...__VLS_functionalComponentArgsRest(__VLS_182));
        __VLS_184.slots.default;
        var __VLS_184;
    }
    if (item.json_path) {
        const __VLS_185 = {}.ATag;
        /** @type {[typeof __VLS_components.ATag, typeof __VLS_components.aTag, typeof __VLS_components.ATag, typeof __VLS_components.aTag, ]} */ ;
        // @ts-ignore
        const __VLS_186 = __VLS_asFunctionalComponent(__VLS_185, new __VLS_185({
            color: "green",
        }));
        const __VLS_187 = __VLS_186({
            color: "green",
        }, ...__VLS_functionalComponentArgsRest(__VLS_186));
        __VLS_188.slots.default;
        var __VLS_188;
    }
    var __VLS_180;
    var __VLS_172;
}
var __VLS_168;
var __VLS_164;
var __VLS_120;
var __VLS_104;
var __VLS_3;
/** @type {__VLS_StyleScopedClasses['app-shell']} */ ;
/** @type {__VLS_StyleScopedClasses['side']} */ ;
/** @type {__VLS_StyleScopedClasses['brand']} */ ;
/** @type {__VLS_StyleScopedClasses['side-stack']} */ ;
/** @type {__VLS_StyleScopedClasses['full']} */ ;
/** @type {__VLS_StyleScopedClasses['full']} */ ;
/** @type {__VLS_StyleScopedClasses['full']} */ ;
/** @type {__VLS_StyleScopedClasses['workspace']} */ ;
/** @type {__VLS_StyleScopedClasses['topbar']} */ ;
/** @type {__VLS_StyleScopedClasses['content-grid']} */ ;
/** @type {__VLS_StyleScopedClasses['table-panel']} */ ;
/** @type {__VLS_StyleScopedClasses['detail-panel']} */ ;
/** @type {__VLS_StyleScopedClasses['code-block']} */ ;
/** @type {__VLS_StyleScopedClasses['ast-board']} */ ;
/** @type {__VLS_StyleScopedClasses['ast-item']} */ ;
/** @type {__VLS_StyleScopedClasses['ast-item']} */ ;
/** @type {__VLS_StyleScopedClasses['ast-item']} */ ;
/** @type {__VLS_StyleScopedClasses['call-graph']} */ ;
/** @type {__VLS_StyleScopedClasses['graph-nodes']} */ ;
/** @type {__VLS_StyleScopedClasses['graph-node']} */ ;
/** @type {__VLS_StyleScopedClasses['graph-edges']} */ ;
var __VLS_dollars;
const __VLS_self = (await import('vue')).defineComponent({
    setup() {
        return {
            CloudUploadOutlined: CloudUploadOutlined,
            FileSearchOutlined: FileSearchOutlined,
            PlayCircleOutlined: PlayCircleOutlined,
            ReloadOutlined: ReloadOutlined,
            loading: loading,
            selectedProjectId: selectedProjectId,
            selectedTaskId: selectedTaskId,
            scanScope: scanScope,
            enableCppcheck: enableCppcheck,
            enableClang: enableClang,
            cppcheckLevel: cppcheckLevel,
            issues: issues,
            reports: reports,
            activeIssue: activeIssue,
            activeCallNodes: activeCallNodes,
            activeCallEdges: activeCallEdges,
            activeAstTypes: activeAstTypes,
            projectOptions: projectOptions,
            taskOptions: taskOptions,
            colorForRisk: colorForRisk,
            issueColumns: issueColumns,
            refreshAll: refreshAll,
            refreshTaskData: refreshTaskData,
            uploadProps: uploadProps,
            onUploadChange: onUploadChange,
            submitTask: submitTask,
            rerunSelectedTask: rerunSelectedTask,
        };
    },
});
export default (await import('vue')).defineComponent({
    setup() {
        return {};
    },
});
; /* PartiallyEnd: #4569/main.vue */
