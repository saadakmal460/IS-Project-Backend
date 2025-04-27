const axios = require("axios");
const FormData = require("form-data");

exports.summarize = async (req, res) => {
  try {
    const formData = new FormData();

    formData.append("file_extension", req.body.file_extension);
    formData.append("file", req.files.file.data, { filename: req.files.file.name });
    formData.append("data", req.files.data.data, { filename: req.files.data.name });
    formData.append("key", req.files.key.data, { filename: req.files.key.name });
    formData.append("iv", req.files.iv.data, { filename: req.files.iv.name });
    formData.append("auth_tag", req.files.auth_tag.data, { filename: req.files.auth_tag.name });
    formData.append("signature", req.files.signature.data, { filename: req.files.signature.name });
    formData.append("publicKey", req.body.publicKey);
    formData.append("captcha_token", req.body.captcha_token);

    // Important: Get headers from formData
    const headers = formData.getHeaders();

    // Send formData with correct headers
    const response = await axios.post("http://localhost:8000/summarize", formData, { headers });

    return res.json(response.data);
  } catch (error) {
    console.error("Error forwarding to Flask API:", error.response?.data || error.message);
    return res.status(500).json({ error: "An error occurred while processing your request." });
  }
};
