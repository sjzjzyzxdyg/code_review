import axios from "axios";
const client = axios.create({
    baseURL: "/api/v1"
});
export async function uploadProject(file) {
    const body = new FormData();
    body.append("file", file);
    const response = await client.post("/projects/upload", body);
    return response.data;
}
export async function listProjects() {
    const response = await client.get("/projects");
    return response.data;
}
export async function createTask(payload) {
    const response = await client.post("/review-tasks", payload);
    return response.data;
}
export async function runTask(taskId) {
    const response = await client.post(`/review-tasks/${taskId}/run`);
    return response.data;
}
export async function listTasks() {
    const response = await client.get("/review-tasks");
    return response.data;
}
export async function listIssues(taskId) {
    const response = await client.get("/issues", { params: { task_id: taskId } });
    return response.data;
}
export async function listReports(taskId) {
    const response = await client.get("/reports", { params: { task_id: taskId } });
    return response.data;
}
