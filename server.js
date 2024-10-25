const express = require("express");
const axios = require("axios");
const crypto = require("crypto");

const app = express();
const PORT = 3000;

app.use(express.json()); // Para manejar JSON en el body de las solicitudes

// Función para verificar vulnerabilidad de contraseña
async function checkPasswordVulnerability(password) {
  const sha1Password = crypto.createHash("sha1").update(password).digest("hex").toUpperCase();
  const prefix = sha1Password.slice(0, 5);
  const suffix = sha1Password.slice(5);

  try {
    const url = `https://api.pwnedpasswords.com/range/${prefix}`;
    const response = await axios.get(url, {
      headers: { "User-Agent": "Node-HIBP-Client" },
    });

    const hashes = response.data.split("\n");
    for (const line of hashes) {
      const [hashSuffix, count] = line.split(":");
      if (hashSuffix === suffix) {
        return `La contraseña ha sido encontrada ${count} veces en brechas de datos.`;
      }
    }

    return "La contraseña no ha sido encontrada en brechas de datos.";
  } catch (error) {
    console.error("Error al consultar el API de HIBP:", error);
    throw new Error("No se pudo verificar la contraseña.");
  }
}

// Endpoint para verificar la contraseña
app.post("/check-password", async (req, res) => {
  const { password } = req.body;

  if (!password) {
    return res.status(400).json({ error: "Se requiere una contraseña para verificar." });
  }

  try {
    const result = await checkPasswordVulnerability(password);
    res.json({ message: result });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Iniciar el servidor
app.listen(PORT, () => {
  console.log(`Servidor escuchando en http://localhost:${PORT}`);
});
