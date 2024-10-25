import { Box, Card, CardMedia, Grid2 } from "@mui/material";
import React from "react";

const MainImage = ({ imgSrc }) => {
  return (
    <Grid2 xs={12} sm={8} sx={{ paddingLeft: 0, paddingRight: 0, margin: 0 }}>
      <Box
        id="slider-for"
        sx={{ position: "relative", width: "100%", overflow: "hidden" }}
      >
        <Card>
          <CardMedia
            component="img"
            image={imgSrc}
            alt="Main Slider Image"
            sx={{ width: "100%" }}
          />
        </Card>
      </Box>
    </Grid2>
  );
};

export default MainImage;
