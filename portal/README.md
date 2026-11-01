# Portal para organizaciones

Aplicación Angular del BANCO KIKE API PLATFORM. La API y las instrucciones de configuración local/despliegue están en el [README del proyecto](../README.md).

## Desarrollo

Instala dependencias con `npm install` desde esta carpeta y ejecuta `npm start`. La API local debe escuchar en `http://localhost:3000`; el portal usa `http://localhost:4200` como origen permitido durante desarrollo.

## Compilación y pruebas

- `npm run build`
- `npm test -- --watch=false`

La aplicación de producción usa `https://api.bancokike.com` como API. No guardar API keys en el bundle ni en almacenamiento del navegador.
