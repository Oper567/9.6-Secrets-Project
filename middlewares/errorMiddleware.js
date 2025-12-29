export const notFound = (req, res, next) => {
  res.status(404);
  res.render("404", { url: req.originalUrl });
};

export const errorHandler = (err, req, res, next) => {
  console.error(err.stack);
  res.status(err.status || 500).json({
    success: false,
    message: err.message || "Server Error",
  });
};
