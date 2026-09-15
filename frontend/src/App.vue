<script setup lang="ts">
import { computed, onMounted, ref } from "vue";
import { theme as antTheme } from "ant-design-vue";
import {
  CloudUploadOutlined,
  FileSearchOutlined,
  FolderOpenOutlined,
  PlayCircleOutlined,
  ReloadOutlined,
  SafetyCertificateOutlined,
  ScheduleOutlined
} from "@ant-design/icons-vue";
import type { UploadChangeParam, UploadProps } from "ant-design-vue";
import {
  createTask,
  listIssues,
  listProjects,
  listReports,
  listTasks,
  registerLocalFiles,
  registerLocalProject,
  runTask,
  uploadProject,
  type Project,
  type ReviewIssue,
  type ReviewReport,
  type ReviewTask
} from "./api";

const loading = ref(false);
const localFolderPath = ref("");
const localFilePaths = ref("");
const selectedProjectId = ref<string>();
const selectedTaskId = ref<string>();
const scanScope = ref(".");
const enableCppcheck = ref(true);
const enableClang = ref(false);
const cppcheckLevel = ref("all");
const projects = ref<Project[]>([]);
const tasks = ref<ReviewTask[]>([]);
const issues = ref<ReviewIssue[]>([]);
const reports = ref<ReviewReport[]>([]);
const activeIssue = ref<ReviewIssue>();

const accentColor = "#6366f1";
const appTheme = {
  token: {
    colorPrimary: accentColor,
    borderRadius: 8
  }
};
const sideTheme = {
  algorithm: antTheme.darkAlgorithm,
  token: {
    colorPrimary: accentColor,
    borderRadius: 8,
    colorBgContainer: "#1b2333",
    colorBgLayout: "#141a29"
  }
};

const activeCallNodes = computed(() => activeIssue.value?.call_chain_graph?.nodes ?? []);
const activeCallEdges = computed(() => activeIssue.value?.call_chain_graph?.edges ?? []);
const activeAstTypes = computed(() => activeIssue.value?.ast_context?.types ?? []);

const projectOptions = computed(() =>
  projects.value.map((project) => ({ label: project.name, value: project.id }))
);

const taskOptions = computed(() =>
  tasks.value.map((task) => ({
    label: `${task.id.slice(0, 8)} - ${task.status}`,
    value: task.id
  }))
);

const riskColor: Record<ReviewIssue["risk_level"], string> = {
  critical: "red",
  high: "volcano",
  medium: "gold",
  low: "green"
};

function colorForRisk(risk: ReviewIssue["risk_level"]) {
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
  } finally {
    loading.value = false;
  }
}

async function refreshTaskData() {
  issues.value = await listIssues(selectedTaskId.value);
  reports.value = await listReports(selectedTaskId.value);
  activeIssue.value = issues.value[0];
}

const uploadProps: UploadProps = {
  accept: ".zip",
  maxCount: 1,
  showUploadList: false,
  customRequest: async ({ file, onSuccess, onError }) => {
    try {
      const project = await uploadProject(file as File);
      projects.value = await listProjects();
      selectedProjectId.value = project.id;
      onSuccess?.(project);
    } catch (error) {
      onError?.(error as Error);
    }
  }
};

async function registerFiles() {
  const paths = localFilePaths.value
    .split("\n")
    .map((l) => l.trim())
    .filter(Boolean);
  if (!paths.length) return;
  loading.value = true;
  try {
    const project = await registerLocalFiles(paths);
    projects.value = await listProjects();
    selectedProjectId.value = project.id;
    localFilePaths.value = "";
  } finally {
    loading.value = false;
  }
}

async function registerLocalPath() {
  const path = localFolderPath.value.trim();
  if (!path) return;
  loading.value = true;
  try {
    const project = await registerLocalProject(path);
    projects.value = await listProjects();
    selectedProjectId.value = project.id;
    localFolderPath.value = "";
  } finally {
    loading.value = false;
  }
}

async function onUploadChange(info: UploadChangeParam) {
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
  } finally {
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
  } finally {
    loading.value = false;
  }
}

onMounted(refreshAll);
</script>

<template>
  <a-config-provider :theme="appTheme">
  <a-layout class="app-shell">
    <a-config-provider :theme="sideTheme">
    <a-layout-sider class="side" width="280">
      <div class="brand">
        <FileSearchOutlined />
        <span>AI Code Review</span>
      </div>

      <div class="side-stack">
        <section class="side-card">
          <h2><FolderOpenOutlined /> Project</h2>
          <a-upload v-bind="uploadProps" @change="onUploadChange">
            <a-button block>
              <CloudUploadOutlined />
              Upload ZIP
            </a-button>
          </a-upload>
          <a-input-search
            v-model:value="localFolderPath"
            placeholder="Local folder path"
            enter-button="Register"
            @search="registerLocalPath"
          />
          <a-textarea
            v-model:value="localFilePaths"
            placeholder="File paths, one per line"
            :rows="3"
          />
          <a-button block @click="registerFiles">Register Files</a-button>
          <a-select
            v-model:value="selectedProjectId"
            class="full"
            :options="projectOptions"
            placeholder="Select project"
          />
        </section>

        <section class="side-card">
          <h2><SafetyCertificateOutlined /> Rules</h2>
          <div class="checkbox-row">
            <a-checkbox v-model:checked="enableCppcheck">Cppcheck</a-checkbox>
            <a-checkbox v-model:checked="enableClang">Clang Analyzer</a-checkbox>
          </div>
          <a-select v-model:value="cppcheckLevel" class="full">
            <a-select-option value="all">all</a-select-option>
            <a-select-option value="warning">warning</a-select-option>
            <a-select-option value="style">style</a-select-option>
            <a-select-option value="performance">performance</a-select-option>
          </a-select>
          <a-input v-model:value="scanScope" addon-before="Scope" />
          <a-button type="primary" block @click="submitTask(true)">
            <PlayCircleOutlined />
            Create & Run
          </a-button>
        </section>

        <section class="side-card">
          <h2><ScheduleOutlined /> Task</h2>
          <a-select
            v-model:value="selectedTaskId"
            class="full"
            :options="taskOptions"
            placeholder="Select task"
            @change="refreshTaskData"
          />
          <a-button block @click="rerunSelectedTask">
            <ReloadOutlined />
            Run Again
          </a-button>
        </section>
      </div>
    </a-layout-sider>
    </a-config-provider>

    <a-layout-content class="workspace">
      <header class="topbar">
        <div>
          <h1>Review Console</h1>
          <p>{{ issues.length }} issues - {{ reports.length }} reports</p>
        </div>
        <a-button :loading="loading" @click="refreshAll">
          <ReloadOutlined />
          Refresh
        </a-button>
      </header>

      <a-tabs>
        <a-tab-pane key="issues" tab="Issues">
          <div class="content-grid">
            <section class="table-panel">
              <a-table
                :columns="issueColumns"
                :data-source="issues"
                :row-key="(record: ReviewIssue) => record.id"
                :pagination="{ pageSize: 8 }"
                :locale="{ emptyText: 'No issues yet. Register a project and run a task to see results here.' }"
                size="middle"
                @row="(record: ReviewIssue) => ({
                  onClick: () => (activeIssue = record),
                  class: activeIssue?.id === record.id ? 'row-active' : ''
                })"
              >
                <template #bodyCell="{ column, record }">
                  <template v-if="column.key === 'risk_level'">
                    <a-tag :color="colorForRisk(record.risk_level)">{{ record.risk_level }}</a-tag>
                  </template>
                  <template v-if="column.key === 'location'">
                    <span>{{ record.file_path }}:{{ record.line }}</span>
                  </template>
                  <template v-if="column.key === 'confidence'">
                    <a-progress
                      :percent="Math.round(record.confidence * 100)"
                      size="small"
                      :show-info="false"
                    />
                  </template>
                </template>
              </a-table>
            </section>

            <aside class="detail-panel" v-if="activeIssue">
              <h2>{{ activeIssue.issue_type }}</h2>
              <a-descriptions size="small" :column="1" bordered>
                <a-descriptions-item label="Location">
                  {{ activeIssue.file_path }}:{{ activeIssue.line }}
                </a-descriptions-item>
                <a-descriptions-item label="Reason">{{ activeIssue.reason }}</a-descriptions-item>
                <a-descriptions-item label="Fix">{{ activeIssue.fix_suggestion }}</a-descriptions-item>
                <a-descriptions-item label="AST">{{ activeIssue.ast_summary || "N/A" }}</a-descriptions-item>
              </a-descriptions>

              <div class="code-block">
                <pre>{{ activeIssue.code_snippet || "No snippet available." }}</pre>
              </div>

              <div class="ast-board">
                <div class="ast-item">
                  <span>Function</span>
                  <strong>{{ activeIssue.ast_context?.function || "N/A" }}</strong>
                </div>
                <div class="ast-item">
                  <span>Types</span>
                  <strong>{{ activeAstTypes.map((item) => `${item.kind} ${item.name}`).join(", ") || "N/A" }}</strong>
                </div>
                <div class="ast-item">
                  <span>Dependencies</span>
                  <strong>{{ activeIssue.dependencies.length }}</strong>
                </div>
              </div>

              <div class="call-graph" v-if="activeCallNodes.length">
                <div class="graph-nodes">
                  <span
                    v-for="node in activeCallNodes"
                    :key="node.id"
                    class="graph-node"
                    :class="{ active: node.in_chain }"
                  >
                    {{ node.name }}
                  </span>
                </div>
                <div class="graph-edges" v-if="activeCallEdges.length">
                  <span v-for="edge in activeCallEdges" :key="`${edge.source}-${edge.target}`">
                    {{ edge.source }} -> {{ edge.target }}
                  </span>
                </div>
              </div>
            </aside>
          </div>
        </a-tab-pane>

        <a-tab-pane key="reports" tab="Reports">
          <a-list
            :data-source="reports"
            bordered
            :locale="{ emptyText: 'No reports yet. Run a review task to generate one.' }"
          >
            <template #renderItem="{ item }">
              <a-list-item>
                <a-list-item-meta :title="item.summary" :description="item.created_at" />
                <a-space>
                  <a-tag v-if="item.markdown_path">Markdown</a-tag>
                  <a-tag v-if="item.json_path" color="green">JSON</a-tag>
                </a-space>
              </a-list-item>
            </template>
          </a-list>
        </a-tab-pane>
      </a-tabs>
    </a-layout-content>
  </a-layout>
  </a-config-provider>
</template>
