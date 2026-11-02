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
  private readonly destroyRef = inject(DestroyRef);
  private adminRefreshStarted = false;
  protected email = '';
  protected password = '';
  protected organizationName = '';
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
        { organizationName: this.organizationName, email: this.email, password: this.password },
        { withCredentials: true },
      ).subscribe({
        next: () => {
          this.password = '';
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
    this.http.post<{ key: string }>(`${apiBase}/v1/applications/${application.id}/keys`, {}, { withCredentials: true }).subscribe({
      next: (result) => {
        this.createdKey.set(result.key);
        this.loadKeys(application);
        this.message.set('La clave solo se muestra ahora. Cópiala a un gestor de secretos; no la insertes en JavaScript público.');
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
        this.adminOrganizationsLoaded.set(false);
        this.adminOrganizationsError.set(false);
        this.adminRequests.set([]);
        this.adminUsageError.set(false);
        this.usage.set(null);
        this.createdKey.set('');
      },
      error: (error: HttpErrorResponse) => this.showError(error),
    });
  }

  protected hideKey() {
    this.createdKey.set('');
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
    const expandedOrganizationId = this.expandedAdminOrganizationId();
    if (expandedOrganizationId) this.loadAdminApplications(expandedOrganizationId);
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
    };
    this.error.set((code ? messages[code] : undefined) ?? 'No se pudo completar la solicitud. Verifica la conexión y vuelve a intentarlo.');
  }
}
