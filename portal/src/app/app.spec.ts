import { TestBed } from '@angular/core/testing';
import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { App } from './app';

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

  it('should show pending organization requests only after platform admin authentication', async () => {
    const fixture = TestBed.createComponent(App);
    const http = TestBed.inject(HttpTestingController);
    fixture.detectChanges();

    http.expectOne((request) => request.url.endsWith('/v1/me'))
      .flush({ role: 'platform_admin' });
    http.expectOne((request) => request.url.endsWith('/v1/admin/organizations'))
      .flush({
        organizations: [
          {
            id: 'pending-org',
            name: 'Pendiente',
            status: 'pending',
            created_at: '2026-11-01T00:00:00.000Z',
            member_count: 1,
            application_count: 0,
          },
          {
            id: 'active-org',
            name: 'Activa',
            status: 'active',
            created_at: '2026-10-01T00:00:00.000Z',
            member_count: 2,
            application_count: 1,
          },
        ],
      });
    http.expectOne((request) => request.url.endsWith('/v1/admin/usage/summary'))
      .flush({ today: 0, last_7_days: 0, this_month: 0, errors: 0 });

    fixture.detectChanges();
    await fixture.whenStable();

    const compiled = fixture.nativeElement as HTMLElement;
    expect(compiled.textContent).toContain('Administración de organizaciones');
    expect(Array.from(compiled.querySelectorAll('.admin-org-details strong')).map((item) => item.textContent?.trim()))
      .toEqual(['Pendiente']);
    http.verify();
  });
});
