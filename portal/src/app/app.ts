import { HttpClient, HttpErrorResponse } from '@angular/common/http';
import { Component, computed, DestroyRef, inject, signal } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import { interval } from 'rxjs';

interface Organization {
  id?: string;
  name?: string;
  status?: string;
  api_enabled?: boolean;
  email?: string;
  role: string;
}

interface AdminOrganization {
  id: string;
  name: string;
  status: string;
  api_enabled: boolean;
  created_at: string;
  member_count: number;
  application_count: number;
}

type AdminRoleId = 'org_owner' | 'org_admin' | 'org_member' | 'platform_admin';

interface AdminRole {
  id: AdminRoleId;
  label: string;
  scope: string;
}

interface AdminUser {
  id: string;
  full_name: string | null;
  email: string;
  organization_id: string | null;
  organization_name: string | null;
  role: AdminRoleId;
  active: boolean;
  created_at: string;
}

interface AdminUserAudit {
  id: number;
  actor_user_id: string;
  actor_email: string | null;
  target_user_id: string;
  target_email: string | null;
  organization_id: string | null;
  organization_name: string | null;
  action: 'role_changed' | 'account_status_changed';
  previous_role: AdminRoleId;
  new_role: AdminRoleId;
  previous_active: boolean;
  new_active: boolean;
  outcome: 'success' | 'rejected';
  created_at: string;
}

interface PendingRoleChange {
  user: AdminUser;
  role: AdminRoleId;
  organizationId: string | null;
}

type OrganizationFilter = 'pending' | 'all' | 'active' | 'rejected' | 'suspended';

interface Application {
  id: string;
  name: string;
  environment: string;
  api_enabled: boolean;
  created_at: string;
}

interface ApiKeyMetadata {
  id: string;
  public_id: string;
  created_at: string;
  expires_at: string | null;
  revoked_at: string | null;
  last_used_at: string | null;
}

interface AdminApplication extends Application {
  keys: ApiKeyMetadata[];
}

interface UsageSummary {
  today: number;
  last_7_days: number;
  this_month: number;
  errors: number;
}

interface AdminApiRequest {
  id: string;
  organization_name: string;
  application_name: string;
  origin_domain: string | null;
  endpoint: string;
  method: string;
  status_code: number;
  duration_ms: number;
  created_at: string;
}

interface AdminUsage extends UsageSummary {
  requests: AdminApiRequest[];
}

const apiBase = location.hostname === 'localhost' ? 'http://localhost:3000' : 'https://apibanco-4ytc.onrender.com';

@Component({
  imports: [CommonModule, FormsModule],
  selector: 'app-root',
  styleUrl: './app.scss',
  templateUrl: './app.html',
})
export class App {
  protected readonly apiDocsUrl = `${apiBase}/docs`;
  private readonly http = inject(HttpClient);
  protected readonly organization = signal<Organization | null>(null);
  protected readonly applications = signal<Application[]>([]);
  protected readonly apiKeys = signal<Record<string, ApiKeyMetadata[]>>({});
  protected readonly organizations = signal<AdminOrganization[]>([]);
  protected readonly adminApplications = signal<Record<string, AdminApplication[]>>({});
  protected readonly expandedAdminOrganizationId = signal<string | null>(null);
  protected readonly adminApplicationsLoading = signal<string | null>(null);
  protected readonly adminApplicationsError = signal<string | null>(null);
  protected readonly adminAction = signal<string | null>(null);
  protected readonly adminRoles = signal<AdminRole[]>([]);
  protected readonly adminUsers = signal<AdminUser[]>([]);
  protected readonly adminUsersTotal = signal(0);
  protected readonly adminUsersPage = signal(1);
  protected readonly adminUsersPageSize = 25;
  protected readonly adminUsersLastPage = computed(
    () => Math.max(1, Math.ceil(this.adminUsersTotal() / this.adminUsersPageSize)),
  );
  protected readonly adminUsersLoading = signal(false);
  protected readonly adminUsersError = signal(false);
  protected readonly adminUserSearch = signal('');
  protected readonly adminUserRoleFilter = signal('');
  protected readonly adminUserOrganizationFilter = signal('');
  protected readonly adminUserActiveFilter = signal('');
  protected readonly adminUserRoleDrafts = signal<Record<string, AdminRoleId>>({});
  protected readonly adminUserOrganizationDrafts = signal<Record<string, string>>({});
  protected readonly pendingRoleChange = signal<PendingRoleChange | null>(null);
  protected readonly pendingStatusChange = signal<{ user: AdminUser; active: boolean } | null>(null);
  protected readonly adminUserMutation = signal(false);
  protected readonly adminAuditLogs = signal<AdminUserAudit[]>([]);
  protected readonly adminAuditTotal = signal(0);
  protected readonly adminAuditPage = signal(1);
  protected readonly adminAuditLastPage = computed(
    () => Math.max(1, Math.ceil(this.adminAuditTotal() / this.adminUsersPageSize)),
  );
  protected readonly adminAuditLoading = signal(false);
  protected readonly adminAuditError = signal(false);
  protected readonly organizationFilter = signal<OrganizationFilter>('pending');
  protected readonly filteredOrganizations = computed(() => {
    const filter = this.organizationFilter();
    const organizations = this.organizations();
    return filter === 'all' ? organizations : organizations.filter((organization) => organization.status === filter);
  });
  protected readonly pendingOrganizationCount = computed(
    () => this.organizations().filter((organization) => organization.status === 'pending').length,
  );
  protected readonly activeOrganizationCount = computed(
    () => this.organizations().filter((organization) => organization.status === 'active').length,
  );
  protected readonly usage = signal<UsageSummary | null>(null);
  protected readonly adminRequests = signal<AdminApiRequest[]>([]);
  protected readonly isPlatformAdmin = signal(false);
  protected readonly adminOrganizationsLoading = signal(false);
  protected readonly adminOrganizationsLoaded = signal(false);
  protected readonly adminOrganizationsError = signal(false);
  protected readonly adminUsageLoading = signal(false);
  protected readonly adminUsageError = signal(false);
  protected readonly canManage = signal(false);
  protected readonly error = signal('');
  protected readonly message = signal('');
  protected readonly loading = signal(false);
  protected readonly registerMode = signal(false);
  protected readonly createdKey = signal('');
  protected readonly isKeyVisible = signal(false);
  private readonly destroyRef = inject(DestroyRef);
  private adminRefreshStarted = false;
  private adminUsersRequestId = 0;
  private adminAuditRequestId = 0;
  protected email = '';
  protected password = '';
  protected organizationName = '';
  protected fullName = '';
  protected applicationName = '';

  constructor() {
    this.http.get<Organization>(`${apiBase}/v1/me`, { withCredentials: true }).subscribe({
      next: (organization) => {
        this.organization.set(organization);
        this.canManage.set(['org_owner', 'org_admin'].includes(organization.role));
        if (organization.role === 'platform_admin') {
          this.isPlatformAdmin.set(true);
          this.loadAdminData();
          this.startAdminRefresh();
          return;
        }
        this.loadApplications();
        this.loadUsage();
      },
      error: (error: HttpErrorResponse) => {
        if (error.status !== 401) this.showError(error);
      },
    });
  }

  protected toggleMode() {
    this.registerMode.update((mode) => !mode);
    this.error.set('');
    this.message.set('');
  }

  protected submitAuth() {
    this.loading.set(true);
    this.error.set('');
    this.message.set('');
    if (this.registerMode()) {
      this.http.post<{ organizationId: string; status: string }>(
        `${apiBase}/v1/organizations`,
        { organizationName: this.organizationName, fullName: this.fullName, email: this.email, password: this.password },
        { withCredentials: true },
      ).subscribe({
        next: () => {
          this.password = '';
          this.fullName = '';
          this.message.set('Registro recibido. La organización debe completar la verificación y aprobación antes de activar integraciones.');
          this.registerMode.set(false);
          this.loading.set(false);
        },
        error: (error: HttpErrorResponse) => this.showError(error),
      });
      return;
    }

    this.http.post(`${apiBase}/v1/auth/login`, { email: this.email, password: this.password }, { withCredentials: true }).subscribe({
      next: () => this.http.get<Organization>(`${apiBase}/v1/me`, { withCredentials: true }).subscribe({
        next: (organization) => {
          this.password = '';
          this.organization.set(organization);
          this.loading.set(false);
          this.canManage.set(['org_owner', 'org_admin'].includes(organization.role));
          if (organization.role === 'platform_admin') {
            this.isPlatformAdmin.set(true);
            this.loadAdminData();
            this.startAdminRefresh();
          } else {
            this.loadApplications();
            this.loadUsage();
          }
        },
        error: (error: HttpErrorResponse) => this.showError(error),
      }),
      error: (error: HttpErrorResponse) => this.showError(error),
    });
  }

  protected createApplication() {
    this.error.set('');
    this.message.set('');
    this.http.post<Application>(`${apiBase}/v1/applications`, { name: this.applicationName }, { withCredentials: true }).subscribe({
      next: (application) => {
        this.applicationName = '';
        this.applications.update((items) => [application, ...items]);
        this.apiKeys.update((keys) => ({ ...keys, [application.id]: [] }));
        this.message.set('Aplicación Sandbox creada.');
      },
      error: (error: HttpErrorResponse) => this.showError(error),
    });
  }

  protected createKey(application: Application) {
    this.error.set('');
    this.createdKey.set('');
    this.isKeyVisible.set(false);
    this.http.post<{ key: string }>(`${apiBase}/v1/applications/${application.id}/keys`, {}, { withCredentials: true }).subscribe({
      next: (result) => {
        this.createdKey.set(result.key);
        this.isKeyVisible.set(true);
        this.loadKeys(application);
        this.message.set('Puedes mostrar u ocultar la clave durante esta sesión. Cópiala a un gestor de secretos; no la insertes en JavaScript público.');
      },
      error: (error: HttpErrorResponse) => this.showError(error),
    });
  }

  protected logout() {
    this.http.post(`${apiBase}/v1/auth/logout`, {}, { withCredentials: true }).subscribe({
      next: () => {
        this.organization.set(null);
        this.isPlatformAdmin.set(false);
        this.canManage.set(false);
        this.applications.set([]);
        this.apiKeys.set({});
        this.organizations.set([]);
        this.adminApplications.set({});
        this.expandedAdminOrganizationId.set(null);
        this.adminApplicationsLoading.set(null);
        this.adminApplicationsError.set(null);
        this.adminAction.set(null);
        this.adminUsers.set([]);
        this.adminUsersTotal.set(0);
        this.adminUsersPage.set(1);
        this.adminUsersError.set(false);
        this.adminRoles.set([]);
        this.adminAuditLogs.set([]);
        this.adminAuditTotal.set(0);
        this.adminAuditError.set(false);
        this.pendingRoleChange.set(null);
        this.pendingStatusChange.set(null);
        this.adminOrganizationsLoaded.set(false);
        this.adminOrganizationsError.set(false);
        this.adminRequests.set([]);
        this.adminUsageError.set(false);
        this.usage.set(null);
        this.createdKey.set('');
        this.isKeyVisible.set(false);
      },
      error: (error: HttpErrorResponse) => this.showError(error),
    });
  }

  protected toggleKeyVisibility() {
    this.isKeyVisible.update((visible) => !visible);
  }

  private loadApplications() {
    this.http.get<{ applications: Application[] }>(`${apiBase}/v1/applications`, { withCredentials: true }).subscribe({
      next: (result) => {
        this.applications.set(result.applications);
        if (this.canManage()) result.applications.forEach((application) => this.loadKeys(application));
      },
      error: (error: HttpErrorResponse) => this.showError(error),
    });
  }

  protected revokeKey(application: Application, key: ApiKeyMetadata) {
    this.error.set('');
    this.http.delete(`${apiBase}/v1/applications/${application.id}/keys/${key.id}`, { withCredentials: true }).subscribe({
      next: () => this.apiKeys.update((keys) => ({
        ...keys,
        [application.id]: (keys[application.id] ?? []).map((item) => item.id === key.id ? { ...item, revoked_at: new Date().toISOString() } : item),
      })),
      error: (error: HttpErrorResponse) => this.showError(error),
    });
  }

  private loadKeys(application: Application) {
    this.http.get<{ keys: ApiKeyMetadata[] }>(`${apiBase}/v1/applications/${application.id}/keys`, { withCredentials: true }).subscribe({
      next: (result) => this.apiKeys.update((keys) => ({ ...keys, [application.id]: result.keys })),
      error: (error: HttpErrorResponse) => this.showError(error),
    });
  }

  protected decideOrganization(organization: AdminOrganization, status: 'active' | 'rejected' | 'suspended') {
    this.error.set('');
    this.http.post<AdminOrganization>(
      `${apiBase}/v1/admin/organizations/${organization.id}/decision`,
      { status },
      { withCredentials: true },
    ).subscribe({
      next: (updated) => this.organizations.update((items) => items.map((item) => item.id === updated.id ? { ...item, status: updated.status } : item)),
      error: (error: HttpErrorResponse) => this.showError(error),
    });
  }

  protected toggleOrganizationApiAccess(organization: AdminOrganization) {
    const enabled = !organization.api_enabled;
    this.adminAction.set(`organization:${organization.id}`);
    this.error.set('');
    this.http.post<{ id: string; api_enabled: boolean }>(
      `${apiBase}/v1/admin/organizations/${organization.id}/api-access`,
      { enabled },
      { withCredentials: true },
    ).subscribe({
      next: (updated) => {
        this.organizations.update((items) => items.map((item) => item.id === updated.id
          ? { ...item, api_enabled: updated.api_enabled }
          : item));
        this.adminAction.set(null);
      },
      error: (error: HttpErrorResponse) => {
        this.adminAction.set(null);
        this.showError(error);
      },
    });
  }

  protected toggleAdminApplications(organization: AdminOrganization) {
    if (this.expandedAdminOrganizationId() === organization.id) {
      this.expandedAdminOrganizationId.set(null);
      return;
    }
    this.expandedAdminOrganizationId.set(organization.id);
    this.loadAdminApplications(organization.id);
  }

  protected toggleApplicationApiAccess(organizationId: string, application: AdminApplication) {
    const enabled = !application.api_enabled;
    this.adminAction.set(`application:${application.id}`);
    this.error.set('');
    this.http.post<{ id: string; api_enabled: boolean }>(
      `${apiBase}/v1/admin/applications/${application.id}/api-access`,
      { enabled },
      { withCredentials: true },
    ).subscribe({
      next: (updated) => {
        this.adminApplications.update((applications) => ({
          ...applications,
          [organizationId]: (applications[organizationId] ?? []).map((item) => item.id === updated.id
            ? { ...item, api_enabled: updated.api_enabled }
            : item),
        }));
        this.adminAction.set(null);
      },
      error: (error: HttpErrorResponse) => {
        this.adminAction.set(null);
        this.showError(error);
      },
    });
  }

  protected revokeAdminKey(organizationId: string, application: AdminApplication, key: ApiKeyMetadata) {
    this.adminAction.set(`key:${key.id}`);
    this.error.set('');
    this.http.delete(
      `${apiBase}/v1/admin/organizations/${organizationId}/applications/${application.id}/keys/${key.id}`,
      { withCredentials: true },
    ).subscribe({
      next: () => {
        this.adminApplications.update((applications) => ({
          ...applications,
          [organizationId]: (applications[organizationId] ?? []).map((item) => item.id === application.id
            ? {
              ...item,
              keys: item.keys.map((itemKey) => itemKey.id === key.id
                ? { ...itemKey, revoked_at: new Date().toISOString() }
                : itemKey),
            }
            : item),
        }));
        this.adminAction.set(null);
      },
      error: (error: HttpErrorResponse) => {
        this.adminAction.set(null);
        this.showError(error);
      },
    });
  }

  protected setOrganizationFilter(filter: OrganizationFilter) {
    this.organizationFilter.set(filter);
  }

  protected refreshAdminData() {
    this.loadAdminOrganizations();
    this.loadAdminUsage();
    this.loadAdminUsers();
    this.loadAdminAuditLogs();
    const expandedOrganizationId = this.expandedAdminOrganizationId();
    if (expandedOrganizationId) this.loadAdminApplications(expandedOrganizationId);
  }

  protected searchAdminUsers() {
    this.adminUsersPage.set(1);
    this.loadAdminUsers(1);
  }

  protected filterAdminUsers() {
    this.adminUsersPage.set(1);
    this.loadAdminUsers(1);
  }

  protected changeAdminUsersPage(page: number) {
    if (page < 1 || page > this.adminUsersLastPage()) return;
    this.loadAdminUsers(page);
  }

  protected changeAdminAuditPage(page: number) {
    if (page < 1 || page > this.adminAuditLastPage()) return;
    this.loadAdminAuditLogs(page);
  }

  protected roleLabel(role: AdminRoleId) {
    return this.adminRoles().find((item) => item.id === role)?.label ?? role;
  }

  protected roleScope(role: AdminRoleId) {
    return this.adminRoles().find((item) => item.id === role)?.scope ?? '';
  }

  protected adminOrganizationName(organizationId: string | null) {
    return this.organizations().find((item) => item.id === organizationId)?.name ?? 'la organización seleccionada';
  }

  protected setAdminUserRoleDraft(user: AdminUser, role: AdminRoleId) {
    this.adminUserRoleDrafts.update((drafts) => ({ ...drafts, [user.id]: role }));
    if (role === 'platform_admin') {
      this.adminUserOrganizationDrafts.update((drafts) => ({ ...drafts, [user.id]: '' }));
    } else if (!this.adminUserOrganizationDrafts()[user.id]) {
      this.adminUserOrganizationDrafts.update((drafts) => ({
        ...drafts,
        [user.id]: user.organization_id ?? this.organizations()[0]?.id ?? '',
      }));
    }
  }

  protected setAdminUserOrganizationDraft(userId: string, organizationId: string) {
    this.adminUserOrganizationDrafts.update((drafts) => ({ ...drafts, [userId]: organizationId }));
  }

  protected requestAdminRoleChange(user: AdminUser) {
    const role = this.adminUserRoleDrafts()[user.id] ?? user.role;
    const organizationId = role === 'platform_admin'
      ? null
      : (this.adminUserOrganizationDrafts()[user.id] || user.organization_id);
    if (role === user.role && organizationId === user.organization_id) return;
    this.pendingRoleChange.set({ user, role, organizationId });
  }

  protected requestAdminStatusChange(user: AdminUser) {
    this.pendingStatusChange.set({ user, active: !user.active });
  }

  protected cancelAdminUserChange() {
    this.pendingRoleChange.set(null);
    this.pendingStatusChange.set(null);
  }

  protected confirmAdminRoleChange() {
    const change = this.pendingRoleChange();
    if (!change || this.adminUserMutation()) return;
    this.adminUserMutation.set(true);
    this.error.set('');
    this.message.set('');
    this.http.patch<AdminUser>(
      `${apiBase}/v1/admin/users/${change.user.id}/role`,
      { role: change.role, organizationId: change.organizationId },
      { withCredentials: true },
    ).subscribe({
      next: (updated) => {
        this.adminUserMutation.set(false);
        this.pendingRoleChange.set(null);
        this.message.set(`Rol de ${updated.email} actualizado correctamente.`);
        this.loadAdminUsers();
        this.loadAdminAuditLogs(1);
      },
      error: (error: HttpErrorResponse) => {
        this.adminUserMutation.set(false);
        this.showError(error);
      },
    });
  }

  protected confirmAdminStatusChange() {
    const change = this.pendingStatusChange();
    if (!change || this.adminUserMutation()) return;
    this.adminUserMutation.set(true);
    this.error.set('');
    this.message.set('');
    this.http.patch<AdminUser>(
      `${apiBase}/v1/admin/users/${change.user.id}/status`,
      { active: change.active },
      { withCredentials: true },
    ).subscribe({
      next: (updated) => {
        this.adminUserMutation.set(false);
        this.pendingStatusChange.set(null);
        this.message.set(`La cuenta de ${updated.email} se ${updated.active ? 'activó' : 'desactivó'} correctamente.`);
        this.loadAdminUsers();
        this.loadAdminAuditLogs(1);
      },
      error: (error: HttpErrorResponse) => {
        this.adminUserMutation.set(false);
        this.showError(error);
      },
    });
  }

  private loadUsage() {
    this.http.get<UsageSummary>(`${apiBase}/v1/usage/summary`, { withCredentials: true }).subscribe({
      next: (usage) => this.usage.set(usage),
      error: (error: HttpErrorResponse) => this.showError(error),
    });
  }

  private loadAdminData() {
    this.loadAdminOrganizations();
    this.loadAdminUsage();
    this.loadAdminRoles();
    this.loadAdminUsers(1);
    this.loadAdminAuditLogs(1);
  }

  private loadAdminRoles() {
    this.http.get<{ roles: AdminRole[] }>(`${apiBase}/v1/admin/roles`, { withCredentials: true }).subscribe({
      next: (result) => this.adminRoles.set(result.roles),
      error: (error: HttpErrorResponse) => this.showError(error),
    });
  }

  private loadAdminUsers(page = this.adminUsersPage()) {
    const requestId = ++this.adminUsersRequestId;
    this.adminUsersLoading.set(true);
    this.adminUsersError.set(false);
    const params = new URLSearchParams({
      page: String(page),
      pageSize: String(this.adminUsersPageSize),
    });
    const search = this.adminUserSearch().trim();
    if (search) params.set('search', search);
    if (this.adminUserRoleFilter()) params.set('role', this.adminUserRoleFilter());
    if (this.adminUserOrganizationFilter()) params.set('organizationId', this.adminUserOrganizationFilter());
    if (this.adminUserActiveFilter()) params.set('active', this.adminUserActiveFilter());
    this.http.get<{ users: AdminUser[]; total: number; page: number }>(
      `${apiBase}/v1/admin/users?${params.toString()}`,
      { withCredentials: true },
    ).subscribe({
      next: (result) => {
        if (requestId !== this.adminUsersRequestId) return;
        const lastPage = Math.max(1, Math.ceil(result.total / this.adminUsersPageSize));
        if (page > lastPage) {
          this.adminUsersLoading.set(false);
          this.loadAdminUsers(lastPage);
          return;
        }
        this.adminUsers.set(result.users);
        this.adminUsersTotal.set(result.total);
        this.adminUsersPage.set(result.page);
        this.adminUsersLoading.set(false);
      },
      error: (error: HttpErrorResponse) => {
        if (requestId !== this.adminUsersRequestId) return;
        this.adminUsersError.set(true);
        this.adminUsersLoading.set(false);
        this.showError(error);
      },
    });
  }

  private loadAdminAuditLogs(page = this.adminAuditPage()) {
    const requestId = ++this.adminAuditRequestId;
    this.adminAuditLoading.set(true);
    this.adminAuditError.set(false);
    const params = new URLSearchParams({
      page: String(page),
      pageSize: String(this.adminUsersPageSize),
    });
    this.http.get<{ logs: AdminUserAudit[]; total: number; page: number }>(
      `${apiBase}/v1/admin/audit-logs?${params.toString()}`,
      { withCredentials: true },
    ).subscribe({
      next: (result) => {
        if (requestId !== this.adminAuditRequestId) return;
        this.adminAuditLogs.set(result.logs);
        this.adminAuditTotal.set(result.total);
        this.adminAuditPage.set(result.page);
        this.adminAuditLoading.set(false);
      },
      error: (error: HttpErrorResponse) => {
        if (requestId !== this.adminAuditRequestId) return;
        this.adminAuditError.set(true);
        this.adminAuditLoading.set(false);
        this.showError(error);
      },
    });
  }

  private loadAdminUsage() {
    if (this.adminUsageLoading()) return;
    this.adminUsageLoading.set(true);
    this.http.get<AdminUsage>(`${apiBase}/v1/admin/usage/summary`, { withCredentials: true }).subscribe({
      next: (usage) => {
        const { requests, ...summary } = usage;
        this.usage.set(summary);
        this.adminRequests.set(requests);
        this.adminUsageError.set(false);
        this.adminUsageLoading.set(false);
      },
      error: (error: HttpErrorResponse) => {
        this.adminUsageError.set(true);
        this.adminUsageLoading.set(false);
        this.showError(error);
      },
    });
  }

  private loadAdminOrganizations() {
    if (this.adminOrganizationsLoading()) return;
    this.adminOrganizationsLoading.set(true);
    this.http.get<{ organizations: AdminOrganization[] }>(`${apiBase}/v1/admin/organizations`, { withCredentials: true }).subscribe({
      next: (result) => {
        this.organizations.set(result.organizations);
        this.adminOrganizationsLoaded.set(true);
        this.adminOrganizationsError.set(false);
        this.adminOrganizationsLoading.set(false);
      },
      error: (error: HttpErrorResponse) => {
        this.adminOrganizationsLoaded.set(true);
        this.adminOrganizationsError.set(true);
        this.adminOrganizationsLoading.set(false);
        this.showError(error);
      },
    });
  }

  private loadAdminApplications(organizationId: string) {
    if (this.adminApplicationsLoading() === organizationId) return;
    this.adminApplicationsLoading.set(organizationId);
    this.adminApplicationsError.set(null);
    this.http.get<{ applications: AdminApplication[] }>(
      `${apiBase}/v1/admin/organizations/${organizationId}/applications`,
      { withCredentials: true },
    ).subscribe({
      next: (result) => {
        this.adminApplications.update((applications) => ({ ...applications, [organizationId]: result.applications }));
        this.adminApplicationsLoading.set(null);
      },
      error: (error: HttpErrorResponse) => {
        this.adminApplicationsError.set(organizationId);
        this.adminApplicationsLoading.set(null);
        this.showError(error);
      },
    });
  }

  private startAdminRefresh() {
    if (this.adminRefreshStarted) return;
    this.adminRefreshStarted = true;
    interval(60_000)
      .pipe(takeUntilDestroyed(this.destroyRef))
      .subscribe(() => {
        if (this.isPlatformAdmin()) this.refreshAdminData();
      });
  }

  private showError(error: HttpErrorResponse) {
    this.loading.set(false);
    const code = error.error?.error as string | undefined;
    const messages: Record<string, string> = {
      invalid_credentials: 'Correo o contraseña incorrectos.',
      organization_not_approved: 'La organización todavía no ha sido aprobada.',
      organization_suspended: 'La organización está suspendida. Contacta al administrador.',
      organization_not_active: 'La organización no está activa. Contacta al administrador.',
      production_not_enabled: 'El entorno de producción aún no está habilitado.',
      insufficient_permissions: 'Tu cuenta no tiene permisos para esta acción.',
      email_already_registered: 'Ese correo ya tiene una cuenta.',
      api_access_disabled: 'El administrador todavía no ha habilitado el acceso API para esta organización o aplicación.',
      database_schema_outdated: 'El servicio requiere actualizar la base de datos. El administrador debe aplicar la migración 002_admin_api_access.sql y volver a intentar.',
      self_role_change_not_allowed: 'No puedes modificar tu propio rol.',
      self_status_change_not_allowed: 'No puedes cambiar el estado de tu propia cuenta.',
      last_platform_admin_required: 'No se puede completar la operación: debe existir al menos un administrador de plataforma activo.',
      organization_required_for_role: 'Selecciona una organización para asignar este rol.',
      organization_not_found: 'La organización seleccionada no existe.',
      platform_admin_must_not_have_organization: 'Un administrador de plataforma no puede estar asociado a una organización.',
    };
    if (error.status === 0 && location.hostname === 'localhost') {
      this.error.set('No se pudo conectar con el API local en http://localhost:3000. Verifica api/.env y arranca la API con npm run api:dev.');
      return;
    }
    if (error.status === 503 && code === 'database_schema_outdated') {
      this.error.set(messages['database_schema_outdated']);
      return;
    }
    this.error.set((code ? messages[code] : undefined) ?? 'No se pudo completar la solicitud. Verifica la conexión y vuelve a intentarlo.');
  }
}
