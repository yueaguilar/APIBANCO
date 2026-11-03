import { TestBed } from '@angular/core/testing';
import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { App } from './app';

const adminRoles = [
  { id: 'org_owner', label: 'Propietario de organización', scope: 'Administra su organización.' },
  { id: 'org_admin', label: 'Administrador de organización', scope: 'Administra aplicaciones.' },
  { id: 'org_member', label: 'Miembro de organización', scope: 'Acceso de miembro.' },
  { id: 'platform_admin', label: 'Administrador de plataforma', scope: 'Acceso global.' },
];

function flushAdminManagementRequests(
  http: HttpTestingController,
  users: object[] = [],
  total = users.length,
  includeRoles = true,
) {
  if (includeRoles) {
    http.expectOne((request) => request.url.endsWith('/v1/admin/roles'))
      .flush({ roles: adminRoles });
  }
  http.expectOne((request) => request.url.includes('/v1/admin/users?'))
    .flush({ users, total, page: 1, pageSize: 25 });
  http.expectOne((request) => request.url.includes('/v1/admin/audit-logs?'))
    .flush({ logs: [], total: 0, page: 1, pageSize: 25 });
}

describe('App', () => {
  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [App],
      providers: [provideHttpClient(), provideHttpClientTesting()],
    })
      .compileComponents();
  });

  it('should create the app', () => {
    const fixture = TestBed.createComponent(App);
    const app = fixture.componentInstance;
    expect(app).toBeTruthy();
  });

  it('should render title', async () => {
    const fixture = TestBed.createComponent(App);
    fixture.detectChanges();
    TestBed.inject(HttpTestingController)
      .expectOne((request) => request.url.endsWith('/v1/me'))
      .flush({}, { status: 401, statusText: 'Unauthorized' });
    await fixture.whenStable();
    const compiled = fixture.nativeElement as HTMLElement;
    expect(compiled.querySelector('h1')?.textContent).toContain('Conecta tus servicios');
  });

  it('should show a database migration message when the session profile cannot be loaded', async () => {
    const fixture = TestBed.createComponent(App);
    fixture.detectChanges();
    TestBed.inject(HttpTestingController)
      .expectOne((request) => request.url.endsWith('/v1/me'))
      .flush(
        { error: 'database_schema_outdated', requiredMigration: '002_admin_api_access.sql' },
        { status: 503, statusText: 'Service Unavailable' },
      );
    await fixture.whenStable();
    fixture.detectChanges();

    expect((fixture.nativeElement as HTMLElement).textContent)
      .toContain('El servicio requiere actualizar la base de datos');
    expect((fixture.nativeElement as HTMLElement).textContent)
      .toContain('002_admin_api_access.sql');
  });

  it('should explain how to start the local API when the portal cannot connect', async () => {
    const fixture = TestBed.createComponent(App);
    fixture.detectChanges();
    TestBed.inject(HttpTestingController)
      .expectOne((request) => request.url.endsWith('/v1/me'))
      .error(new ProgressEvent('error'));
    await fixture.whenStable();
    fixture.detectChanges();

    expect((fixture.nativeElement as HTMLElement).textContent)
      .toContain('No se pudo conectar con el API local en http://localhost:3000');
    expect((fixture.nativeElement as HTMLElement).textContent)
      .toContain('npm run api:dev');
  });

  it('should show pending organization requests only after platform admin authentication', async () => {
    const fixture = TestBed.createComponent(App);
    const http = TestBed.inject(HttpTestingController);
    fixture.detectChanges();

    http.expectOne((request) => request.url.endsWith('/v1/me'))
      .flush({ id: 'platform-user', role: 'platform_admin' });
    http.expectOne((request) => request.url.endsWith('/v1/admin/organizations'))
      .flush({
        organizations: [
          {
            id: 'pending-org',
            name: 'Pendiente',
            status: 'pending',
            api_enabled: false,
            created_at: '2026-11-01T00:00:00.000Z',
            member_count: 1,
            application_count: 0,
          },
          {
            id: 'active-org',
            name: 'Activa',
            status: 'active',
            api_enabled: true,
            created_at: '2026-10-01T00:00:00.000Z',
            member_count: 2,
            application_count: 1,
          },
        ],
      });
    http.expectOne((request) => request.url.endsWith('/v1/admin/usage/summary'))
      .flush({ today: 0, last_7_days: 0, this_month: 0, errors: 0, requests: [] });
    flushAdminManagementRequests(http);

    fixture.detectChanges();
    await fixture.whenStable();

    const compiled = fixture.nativeElement as HTMLElement;
    expect(compiled.textContent).toContain('Administración de organizaciones');
    expect(Array.from(compiled.querySelectorAll('.admin-org-details strong')).map((item) => item.textContent?.trim()))
      .toEqual(['Pendiente']);
    http.verify();
  });

  it('should show newly submitted organizations after refreshing the admin list', async () => {
    const fixture = TestBed.createComponent(App);
    const http = TestBed.inject(HttpTestingController);
    fixture.detectChanges();

    http.expectOne((request) => request.url.endsWith('/v1/me'))
      .flush({ id: 'platform-user', role: 'platform_admin' });
    http.expectOne((request) => request.url.endsWith('/v1/admin/organizations'))
      .flush({ organizations: [] });
    http.expectOne((request) => request.url.endsWith('/v1/admin/usage/summary'))
      .flush({ today: 0, last_7_days: 0, this_month: 0, errors: 0, requests: [] });
    flushAdminManagementRequests(http);

    fixture.detectChanges();
    const refreshButton = fixture.nativeElement.querySelector('.admin-panel-heading button') as HTMLButtonElement;
    refreshButton.click();

    http.expectOne((request) => request.url.endsWith('/v1/admin/organizations'))
      .flush({
        organizations: [{
          id: 'new-org',
          name: 'Nueva organización',
          status: 'pending',
          api_enabled: false,
          created_at: '2026-11-02T00:00:00.000Z',
          member_count: 1,
          application_count: 0,
        }],
      });
    http.expectOne((request) => request.url.endsWith('/v1/admin/usage/summary'))
      .flush({
        today: 1,
        last_7_days: 1,
        this_month: 1,
        errors: 0,
        requests: [{
          id: '1',
          organization_name: 'Nueva organización',
          application_name: 'Portal comercio',
          origin_domain: 'comercio.example',
          endpoint: '/v1/integrations/ping',
          method: 'POST',
          status_code: 200,
          duration_ms: 18,
          created_at: '2026-11-02T00:00:00.000Z',
        }],
      });
    flushAdminManagementRequests(http, [{
      id: 'user-id',
      email: 'user@example.com',
      organization_id: 'new-org',
      organization_name: 'Nueva organización',
      role: 'org_member',
      active: true,
      created_at: '2026-11-02T00:00:00.000Z',
    }], 1, false);

    fixture.detectChanges();
    await fixture.whenStable();

    const compiled = fixture.nativeElement as HTMLElement;
    expect(Array.from(compiled.querySelectorAll('.admin-org-details strong')).map((item) => item.textContent?.trim()))
      .toEqual(['Nueva organización']);
    expect(compiled.textContent)
      .toContain('comercio.example');
    expect(compiled.textContent)
      .toContain('Portal comercio');
    expect(compiled.textContent)
      .toContain('/v1/integrations/ping');
    http.verify();
  });

  it('persists organization and application API access changes and reflects key revocation', async () => {
    const fixture = TestBed.createComponent(App);
    const http = TestBed.inject(HttpTestingController);
    fixture.detectChanges();

    http.expectOne((request) => request.url.endsWith('/v1/me'))
      .flush({ id: 'platform-user', role: 'platform_admin' });
    http.expectOne((request) => request.url.endsWith('/v1/admin/organizations'))
      .flush({
        organizations: [{
          id: 'org-id',
          name: 'Comercio',
          status: 'active',
          api_enabled: false,
          created_at: '2026-11-01T00:00:00.000Z',
          member_count: 1,
          application_count: 1,
        }],
      });
    http.expectOne((request) => request.url.endsWith('/v1/admin/usage/summary'))
      .flush({ today: 0, last_7_days: 0, this_month: 0, errors: 0, requests: [] });
    flushAdminManagementRequests(http);
    fixture.detectChanges();

    const buttonByText = (text: string) => Array.from(
      (fixture.nativeElement as HTMLElement).querySelectorAll('button'),
    ).find((button) => button.textContent?.trim() === text) as HTMLButtonElement;

    buttonByText('Todas').click();
    fixture.detectChanges();
    buttonByText('Habilitar API').click();
    const organizationAccess = http.expectOne((request) => request.url.endsWith('/v1/admin/organizations/org-id/api-access'));
    expect(organizationAccess.request.body).toEqual({ enabled: true });
    organizationAccess.flush({ id: 'org-id', api_enabled: true });
    fixture.detectChanges();
    expect(buttonByText('Deshabilitar API')).toBeTruthy();

    buttonByText('Aplicaciones y claves').click();
    http.expectOne((request) => request.url.endsWith('/v1/admin/organizations/org-id/applications'))
      .flush({
        applications: [{
          id: 'app-id',
          name: 'Portal comercio',
          environment: 'sandbox',
          api_enabled: false,
          created_at: '2026-11-01T00:00:00.000Z',
          keys: [{
            id: 'key-id',
            public_id: 'bk_public',
            created_at: '2026-11-01T00:00:00.000Z',
            expires_at: null,
            revoked_at: null,
            last_used_at: null,
          }],
        }],
      });
    fixture.detectChanges();
    expect((fixture.nativeElement as HTMLElement).textContent).toContain('bk_public');

    buttonByText('Habilitar API').click();
    const applicationAccess = http.expectOne((request) => request.url.endsWith('/v1/admin/applications/app-id/api-access'));
    expect(applicationAccess.request.body).toEqual({ enabled: true });
    applicationAccess.flush({ id: 'app-id', api_enabled: true });
    fixture.detectChanges();
    expect((fixture.nativeElement as HTMLElement).textContent).toContain('API habilitada');

    buttonByText('Revocar clave').click();
    http.expectOne((request) => request.url.endsWith('/v1/admin/organizations/org-id/applications/app-id/keys/key-id'))
      .flush(null, { status: 204, statusText: 'No Content' });
    fixture.detectChanges();
    expect((fixture.nativeElement as HTMLElement).textContent).toContain('Revocada');
    http.verify();
  });

  it('can show an API key again after hiding it during the current session', async () => {
    const fixture = TestBed.createComponent(App);
    const http = TestBed.inject(HttpTestingController);
    fixture.detectChanges();

    http.expectOne((request) => request.url.endsWith('/v1/me'))
      .flush({}, { status: 401, statusText: 'Unauthorized' });
    fixture.detectChanges();

    const compiled = fixture.nativeElement as HTMLElement;
    (compiled.querySelector('input[name="email"]') as HTMLInputElement).value = 'owner@example.com';
    compiled.querySelector('input[name="email"]')?.dispatchEvent(new Event('input'));
    (compiled.querySelector('input[name="password"]') as HTMLInputElement).value = 'long-password-value';
    compiled.querySelector('input[name="password"]')?.dispatchEvent(new Event('input'));
    fixture.detectChanges();
    (Array.from(compiled.querySelectorAll('button'))
      .find((button) => button.textContent?.trim() === 'Entrar al portal') as HTMLButtonElement).click();

    http.expectOne((request) => request.url.endsWith('/v1/auth/login')).flush({});
    http.expectOne((request) => request.url.endsWith('/v1/me'))
      .flush({
        id: 'owner-id',
        role: 'org_owner',
        name: 'Comercio',
        email: 'owner@example.com',
        status: 'active',
        api_enabled: true,
      });
    http.expectOne((request) => request.url.endsWith('/v1/applications'))
      .flush({
        applications: [{
          id: 'app-id',
          name: 'Portal comercio',
          environment: 'sandbox',
          api_enabled: true,
          created_at: '2026-11-01T00:00:00.000Z',
        }],
      });
    http.expectOne((request) => request.url.endsWith('/v1/usage/summary'))
      .flush({ today: 0, last_7_days: 0, this_month: 0, errors: 0 });
    fixture.detectChanges();

    (Array.from(compiled.querySelectorAll('button'))
      .find((button) => button.textContent?.trim() === 'Generar API key') as HTMLButtonElement).click();
    http.expectOne((request) => request.url.endsWith('/v1/applications/app-id/keys') && request.method === 'POST')
      .flush({ key: 'bk_sandbox_key-id.secret-value' });
    const keyMetadataRequests = http.match(
      (request) => request.url.endsWith('/v1/applications/app-id/keys') && request.method === 'GET',
    );
    expect(keyMetadataRequests).toHaveLength(2);
    keyMetadataRequests.forEach((request) => request.flush({ keys: [] }));
    fixture.detectChanges();

    const revealButton = () => compiled.querySelector('.key-reveal button') as HTMLButtonElement;
    expect(compiled.querySelector('.key-reveal code')?.textContent)
      .toBe('bk_sandbox_key-id.secret-value');
    revealButton().click();
    fixture.detectChanges();
    expect(compiled.querySelector('.key-reveal code')?.textContent)
      .toBe('••••••••••••••••');
    expect(revealButton().textContent?.trim()).toBe('Mostrar clave');

    revealButton().click();
    fixture.detectChanges();
    expect(compiled.querySelector('.key-reveal code')?.textContent)
      .toBe('bk_sandbox_key-id.secret-value');
    expect(revealButton().textContent?.trim()).toBe('Ocultar clave');
    http.verify();
  });

  it('confirms role changes before sending them and refreshes the audit log', async () => {
    const fixture = TestBed.createComponent(App);
    const http = TestBed.inject(HttpTestingController);
    const user = {
      id: 'org-user',
      email: 'member@example.com',
      organization_id: 'org-id',
      organization_name: 'Comercio',
      role: 'org_member',
      active: true,
      created_at: '2026-11-01T00:00:00.000Z',
    };
    fixture.detectChanges();

    http.expectOne((request) => request.url.endsWith('/v1/me'))
      .flush({ id: 'platform-user', role: 'platform_admin' });
    http.expectOne((request) => request.url.endsWith('/v1/admin/organizations'))
      .flush({
        organizations: [{
          id: 'org-id',
          name: 'Comercio',
          status: 'active',
          api_enabled: true,
          created_at: '2026-11-01T00:00:00.000Z',
          member_count: 1,
          application_count: 0,
        }],
      });
    http.expectOne((request) => request.url.endsWith('/v1/admin/usage/summary'))
      .flush({ today: 0, last_7_days: 0, this_month: 0, errors: 0, requests: [] });
    flushAdminManagementRequests(http, [user]);
    fixture.detectChanges();

    const compiled = fixture.nativeElement as HTMLElement;
    const roleSelector = compiled.querySelector('[aria-label="Rol nuevo para member@example.com"]') as HTMLSelectElement;
    roleSelector.value = 'platform_admin';
    roleSelector.dispatchEvent(new Event('change'));
    fixture.detectChanges();
    (Array.from(compiled.querySelectorAll('button'))
      .find((button) => button.textContent?.trim() === 'Cambiar rol') as HTMLButtonElement).click();
    fixture.detectChanges();

    expect(compiled.querySelector('[role="dialog"]')?.textContent).toContain('desvinculará a la persona de Comercio');
    expect(http.match((request) => request.url.endsWith('/v1/admin/users/org-user/role'))).toHaveLength(0);

    (Array.from(compiled.querySelectorAll('[role="dialog"] button'))
      .find((button) => button.textContent?.trim() === 'Confirmar cambio') as HTMLButtonElement).click();
    const roleRequest = http.expectOne((request) => request.url.endsWith('/v1/admin/users/org-user/role'));
    expect(roleRequest.request.method).toBe('PATCH');
    expect(roleRequest.request.body).toEqual({ role: 'platform_admin', organizationId: null });
    roleRequest.flush({
      ...user,
      organization_id: null,
      organization_name: null,
      role: 'platform_admin',
    });

    http.expectOne((request) => request.url.includes('/v1/admin/users?'))
      .flush({ users: [], total: 0, page: 1, pageSize: 25 });
    http.expectOne((request) => request.url.includes('/v1/admin/audit-logs?'))
      .flush({ logs: [], total: 0, page: 1, pageSize: 25 });

    fixture.detectChanges();
    expect(compiled.textContent).toContain('Rol de member@example.com actualizado correctamente.');
    http.verify();
  });
});
