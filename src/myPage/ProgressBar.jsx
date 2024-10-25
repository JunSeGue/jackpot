import React, { useEffect, useState } from "react";
import LinearProgress from "@mui/material/LinearProgress";
import Box from "@mui/material/Box";
import Typography from "@mui/material/Typography";

export const ProgressBar = ({ value, fundCollection = 1000000 }) => {
  const [progress, setProgress] = useState(0);
  const targetProgress = (value / fundCollection) * 100;

  useEffect(() => {
    const timer = setTimeout(() => {
      if (progress < targetProgress) {
        setProgress((prev) => Math.min(prev + 1, targetProgress)); // 1씩 증가
      }
    }, 30); // 애니메이션 속도 조정

    return () => clearTimeout(timer); // 컴포넌트가 언마운트될 때 타이머 정리
  }, [progress, targetProgress]);

  return (
    <Box
      sx={{
        display: "flex",
        alignItems: "center",
        marginBottom: 2,
        padding: "0 30px",
      }}
    >
      <Box sx={{ width: "200px", mr: 1 }}>
        <LinearProgress
          variant="determinate"
          value={progress}
          sx={{ height: "8px", borderRadius: "2em" }}
        />
      </Box>
      <Box sx={{ minWidth: 35 }}>
        <Typography variant="body2" color="text.secondary">{`${Math.round(
          progress
        )}%`}</Typography>
      </Box>
    </Box>
  );
};
