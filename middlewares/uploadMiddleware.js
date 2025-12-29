import multer from "multer";
import pkg from "multer-storage-cloudinary";
import { v2 as cloudinary } from "cloudinary";

const { CloudinaryStorage } = pkg;

cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET,
  secure: true,
});

const storage = new CloudinaryStorage({
  cloudinary: cloudinary,
  params: {
    folder: "village_square_media",
    resource_type: "auto",
    allowed_formats: ["jpg", "png", "jpeg", "gif", "mp4", "webp"],
  },
});

export const upload = multer({ storage, limits: { fileSize: 50 * 1024 * 1024 } });
