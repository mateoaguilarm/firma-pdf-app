// ============================================================
//  PDF Signer — Backend Express
//  Procesa PDF + certificado .p12 y aplica firma visual
// ============================================================

const express = require('express');
const multer  = require('multer');
const path    = require('path');
const { PDFDocument, rgb, StandardFonts } = require('pdf-lib');
const forge   = require('node-forge');

// Normaliza texto para compatibilidad WinAnsi (pdf-lib Standard Fonts)
function toWinAnsi(str = '') {
  return (str + '')
    .normalize('NFD')
    .replace(/[\u0300-\u036f]/g, '')   // á→a, é→e, ñ→n, ü→u …
    .replace(/[^\x00-\xFF]/g, '?');    // cualquier otro char fuera de Latin-1
}

const app  = express();
const PORT = process.env.PORT || 3000;

// ── Middleware ────────────────────────────────────────────────
app.use(express.json());
app.use(express.static(__dirname));          // sirve index.html y demás estáticos

// ── Multer (en memoria, sin disco) ───────────────────────────
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 50 * 1024 * 1024 },  // 50 MB máx por archivo
});

// ── GET / ─────────────────────────────────────────────────────
app.get('/', (_req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

// ── POST /sign ────────────────────────────────────────────────
app.post(
  '/sign',
  upload.fields([
    { name: 'pdf', maxCount: 1 },
    { name: 'p12', maxCount: 1 },
  ]),
  async (req, res) => {
    try {
      // ── 1. Validar archivos ──────────────────────────────────
      if (!req.files?.pdf?.[0]) return res.status(400).json({ error: 'PDF requerido.' });
      if (!req.files?.p12?.[0]) return res.status(400).json({ error: 'Certificado .p12 requerido.' });

      const pdfBuffer = req.files['pdf'][0].buffer;
      const p12Buffer = req.files['p12'][0].buffer;

      const {
        password   = '',
        signerName = 'Firmante',
        reason     = '',
        location   = '',
        page       = '1',
        x          = '0.1',
        y          = '0.1',
        boxW       = '0.35',
        boxH       = '0.12',
      } = req.body;

      // ── 2. Parsear .p12 para extraer nombre del certificado ──
      let certCN      = toWinAnsi(signerName);
      let certIssuer  = '';
      let certExpiry  = '';

      try {
        const p12Der   = forge.util.binary.raw.encode(new Uint8Array(p12Buffer));
        const p12Asn1  = forge.asn1.fromDer(p12Der);
        const p12Obj   = forge.pkcs12.pkcs12FromAsn1(p12Asn1, false, password);

        const certBags = p12Obj.getBags({ bagType: forge.pki.oids.certBag });
        const bags     = certBags[forge.pki.oids.certBag] || [];

        if (bags.length > 0) {
          const cert   = bags[0].cert;
          const cn     = cert.subject.getField('CN');
          const issuer = cert.issuer.getField('CN') || cert.issuer.getField('O');
          if (cn)     certCN     = toWinAnsi(cn.value);
          if (issuer) certIssuer = toWinAnsi(issuer.value);

          const notAfter = cert.validity.notAfter;
          if (notAfter) {
            certExpiry = notAfter.toLocaleDateString('es-EC', {
              day: '2-digit', month: '2-digit', year: 'numeric',
            });
          }
        }
      } catch (p12Err) {
        console.warn('⚠ No se pudo parsear el .p12 (contraseña incorrecta o archivo dañado):', p12Err.message);
        // Continuamos con el nombre provisto manualmente
      }

      // ── 3. Cargar PDF y seleccionar página ──────────────────
      const pdfDoc    = await PDFDocument.load(pdfBuffer, { ignoreEncryption: true });
      const pages     = pdfDoc.getPages();
      const pageIndex = Math.max(0, Math.min(parseInt(page) - 1, pages.length - 1));
      const pdfPage   = pages[pageIndex];
      const { width: pw, height: ph } = pdfPage.getSize();

      // ── 4. Convertir coordenadas normalizadas → puntos PDF ──
      //   Frontend envía x,y como fracción [0–1] del ancho/alto de la página.
      //   El origen PDF es esquina inferior-izquierda.
      const sigX = parseFloat(x)    * pw;
      const sigY = parseFloat(y)    * ph;   // y ya viene convertido (origen abajo)
      const sigW = parseFloat(boxW) * pw;
      const sigH = parseFloat(boxH) * ph;

      // ── 5. Embeber fuentes ───────────────────────────────────
      const fontReg  = await pdfDoc.embedFont(StandardFonts.Helvetica);
      const fontBold = await pdfDoc.embedFont(StandardFonts.HelveticaBold);

      // ── 6. Paleta de colores ─────────────────────────────────
      const cBlue      = rgb(0 / 255,  61 / 255, 130 / 255);  // #003d82
      const cBlueDark  = rgb(0 / 255,  40 / 255,  90 / 255);
      const cBlueTint  = rgb(235 / 255, 242 / 255, 255 / 255);
      const cWhite     = rgb(1, 1, 1);
      const cGray      = rgb(0.35, 0.35, 0.35);
      const cGrayLight = rgb(0.75, 0.75, 0.75);

      // ── 7. Dibujar caja de firma ─────────────────────────────

      // Fondo
      pdfPage.drawRectangle({
        x: sigX, y: sigY,
        width: sigW, height: sigH,
        color: cBlueTint,
        borderColor: cBlue,
        borderWidth: 1,
        opacity: 0.97,
      });

      // Barra superior azul
      const headerH = sigH * 0.22;
      pdfPage.drawRectangle({
        x: sigX, y: sigY + sigH - headerH,
        width: sigW, height: headerH,
        color: cBlue,
      });

      // Línea decorativa izquierda
      pdfPage.drawRectangle({
        x: sigX, y: sigY,
        width: 3, height: sigH,
        color: cBlueDark,
      });

      // Texto de la barra
      const headerFontSize = Math.max(5, headerH * 0.5);
      pdfPage.drawText('* DOCUMENTO FIRMADO DIGITALMENTE', {
        x: sigX + 7,
        y: sigY + sigH - headerH + (headerH - headerFontSize) / 2 - 1,
        size: headerFontSize,
        font: fontBold,
        color: cWhite,
      });

      // ── 8. Líneas de datos ───────────────────────────────────
      const now      = new Date();
      const dateStr  = now.toLocaleDateString('es-EC', { day: '2-digit', month: '2-digit', year: 'numeric' });
      const timeStr  = now.toLocaleTimeString('es-EC', { hour: '2-digit', minute: '2-digit', second: '2-digit' });

      const rows = [
        { label: 'Firmado por',  value: toWinAnsi(certCN) },
        { label: 'Fecha / Hora', value: `${dateStr}  ${timeStr}` },
        ...(certIssuer ? [{ label: 'Emisor',   value: toWinAnsi(certIssuer) }] : []),
        ...(certExpiry ? [{ label: 'Vigencia', value: `Hasta ${certExpiry}` }] : []),
      ];

      const contentH   = sigH - headerH;
      const rowH       = contentH / (rows.length + 0.5);
      const labelSize  = Math.max(4.5, Math.min(6.5, rowH * 0.38));
      const valueSize  = Math.max(5,   Math.min(7.5, rowH * 0.46));
      const paddingX   = 8;
      const maxChars   = Math.floor((sigW - paddingX * 2) / (valueSize * 0.5));

      rows.forEach((row, i) => {
        const rowY = sigY + sigH - headerH - (i + 1) * rowH + rowH * 0.25;

        pdfPage.drawText(row.label.toUpperCase() + ':', {
          x: sigX + paddingX,
          y: rowY + labelSize + 1,
          size: labelSize,
          font: fontBold,
          color: cBlue,
        });

        let val = row.value || '-';
        if (val.length > maxChars) val = val.substring(0, maxChars - 1) + '.';

        pdfPage.drawText(val, {
          x: sigX + paddingX,
          y: rowY,
          size: valueSize,
          font: fontReg,
          color: cGray,
        });
      });

      // Línea divisoria inferior discreta
      pdfPage.drawLine({
        start: { x: sigX + 6,       y: sigY + 5 },
        end:   { x: sigX + sigW - 6, y: sigY + 5 },
        thickness: 0.4,
        color: cGrayLight,
      });

      // ── 9. Guardar y enviar ──────────────────────────────────
      const signedBytes = await pdfDoc.save();

      res.set({
        'Content-Type':        'application/pdf',
        'Content-Disposition': 'attachment; filename="documento-firmado.pdf"',
        'Content-Length':      signedBytes.length,
      });
      res.end(Buffer.from(signedBytes));

    } catch (err) {
      console.error('❌ Error al firmar:', err);
      res.status(500).json({ error: err.message || 'Error interno al procesar la firma.' });
    }
  }
);

// ── Iniciar servidor ─────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`
  ╔══════════════════════════════════════╗
  ║   PDF Signer  ·  Puerto ${PORT}         ║
  ║   http://localhost:${PORT}             ║
  ╚══════════════════════════════════════╝
  `);
});
