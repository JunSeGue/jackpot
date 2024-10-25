import { Button, Stack } from "@mui/material";
import React from "react";

const PageComponent = ({
  pageInfo,
  totalPages,
  onPageChange,
  onPrev,
  onNext,
}) => {
  const getDisplayedPages = () => {
    let startPage = Math.max(1, pageInfo.page - 4);
    let endPage = Math.min(totalPages, startPage + 9);

    if (endPage - startPage < 9) {
      startPage = Math.max(1, endPage - 9);
    }

    return Array.from(
      { length: endPage - startPage + 1 },
      (_, i) => startPage + i
    );
  };

  return (
    <Stack direction="row" spacing={2} justifyContent="center" mt={6}>
      <Button
        variant="contained"
        onClick={onPrev}
        disabled={pageInfo.page === 1}
      >
        Previous
      </Button>
      <Stack direction="row" justifyContent="center" mt={4} spacing={1}>
        {getDisplayedPages().map((page) => (
          <Button
            key={page}
            variant={pageInfo.page === page ? "contained" : "outlined"}
            onClick={() => onPageChange(page)}
          >
            {page}
          </Button>
        ))}
        <Button
          variant="contained"
          onClick={onNext}
          disabled={pageInfo.page >= totalPages}
        >
          Next
        </Button>
      </Stack>
    </Stack>
  );
};

export default PageComponent;
