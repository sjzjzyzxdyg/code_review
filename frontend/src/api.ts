import axios from "axios";

export type Project = {
  id: string;
  name: string;
  source_type: string;
  local_path?: string;
  created_at: string;
};

export type ReviewTask = {
  id: string;
  project_id: string;
  status: string;
  scan_scope: string;
  rule_config: Record<string, unknown>;
  error_message?: string;
  created_at: string;
  started_at?: string;
  finished_at?: string;
};

export type ReviewIssue = {
  id: string;
  task_id: string;
  tool: string;
  rule_id?: string;
  file_path: string;
  line: number;
  column?: number;
  issue_type: string;
  risk_level: "low" | "medium" | "high" | "critical";
  description: string;
  reason: string;
  fix_suggestion: string;
  confidence: number;
  is_valid: boolean;
  call_chain: string[];
  call_chain_graph: {
    entry?: string | null;
    nodes?: Array<{ id: string; name: string; in_chain?: boolean }>;
    edges?: Array<{ source: string; target: string }>;
  };
  ast_summary?: string;
  ast_context: {
    function?: string | null;
    types?: Array<{ kind: string; name: string }>;
    dependencies?: string[];
  };
  dependencies: string[];
  code_snippet?: string;
  cwe?: string | null;
  sources?: string[];
  review_route?: "consensus" | "review" | "unreviewed" | "quality" | "project-rule" | null;
  created_at: string;
};

export type ReviewReport = {
  id: string;
  task_id: string;
  markdown_path?: string;
  json_path?: string;
  summary: string;
  created_at: string;
};

const client = axios.create({
  baseURL: "/api/v1"
});

// Only set when CODE_REVIEW_API_KEY is enabled on the backend (shared/intranet
// deployments); local single-user usage needs no configuration.
const apiKey = import.meta.env.VITE_API_KEY;
if (apiKey) {
  client.defaults.headers.common["X-API-Key"] = apiKey;
}

export async function registerLocalProject(folderPath: string): Promise<Project> {
  const response = await client.post<Project>("/projects/from-path", { path: folderPath });
  return response.data;
}

export async function registerLocalFiles(filePaths: string[]): Promise<Project> {
  const response = await client.post<Project>("/projects/from-files", { paths: filePaths });
  return response.data;
}

export async function uploadProject(file: File): Promise<Project> {
  const body = new FormData();
  body.append("file", file);
  const response = await client.post<Project>("/projects/upload", body);
  return response.data;
}

export async function listProjects(): Promise<Project[]> {
  const response = await client.get<Project[]>("/projects");
  return response.data;
}

export async function createTask(payload: {
  project_id: string;
  scan_scope: string;
  rule_config: Record<string, unknown>;
  auto_start: boolean;
}): Promise<ReviewTask> {
  const response = await client.post<ReviewTask>("/review-tasks", payload);
  return response.data;
}

export async function runTask(taskId: string): Promise<ReviewTask> {
  const response = await client.post<ReviewTask>(`/review-tasks/${taskId}/run`);
  return response.data;
}

export async function listTasks(): Promise<ReviewTask[]> {
  const response = await client.get<ReviewTask[]>("/review-tasks");
  return response.data;
}

export async function listIssues(taskId?: string): Promise<ReviewIssue[]> {
  const response = await client.get<ReviewIssue[]>("/issues", { params: { task_id: taskId } });
  return response.data;
}

export async function listReports(taskId?: string): Promise<ReviewReport[]> {
  const response = await client.get<ReviewReport[]>("/reports", { params: { task_id: taskId } });
  return response.data;
}
