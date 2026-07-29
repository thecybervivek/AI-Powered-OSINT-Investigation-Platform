import { describe, expect, it, vi, beforeEach } from "vitest";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";

import { ToastProvider } from "@/contexts/ToastContext";
import { NewInvestigationModal } from "@/components/investigations/NewInvestigationModal";
import { investigationService } from "@/services/investigationService";

vi.mock("@/services/investigationService", () => ({
  investigationService: {
    list: vi.fn(),
    createUsername: vi.fn(),
    createEmail: vi.fn(),
    createDomain: vi.fn(),
    createIp: vi.fn(),
    createDns: vi.fn(),
    createUrl: vi.fn(),
    createPhone: vi.fn(),
    createThreatIntelligence: vi.fn(),
    createSocialMedia: vi.fn(),
    createMalware: vi.fn(),
    createRiskAssessment: vi.fn(),
    uploadFile: vi.fn(),
    uploadReverseImage: vi.fn(),
  },
}));

const mockedService = vi.mocked(investigationService);

function renderModal(
  props?: Partial<React.ComponentProps<typeof NewInvestigationModal>>
) {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });

  const onClose = vi.fn();
  const onCreated = vi.fn();

  const utils = render(
    <MemoryRouter>
      <QueryClientProvider client={queryClient}>
        <ToastProvider>
          <NewInvestigationModal
            isOpen
            onClose={onClose}
            onCreated={onCreated}
            {...props}
          />
        </ToastProvider>
      </QueryClientProvider>
    </MemoryRouter>
  );

  return { ...utils, onClose, onCreated };
}

async function selectType(
  user: ReturnType<typeof userEvent.setup>,
  label: string
) {
  await user.click(
    screen.getByRole("button", {
      name: new RegExp(`Start a ${label} investigation`, "i"),
    })
  );
}

describe("NewInvestigationModal", () => {
  beforeEach(() => {
    vi.clearAllMocks();

    mockedService.list.mockResolvedValue({
      items: [],
      total: 0,
      page: 1,
      page_size: 25,
      total_pages: 0,
    });
  });

  it("opens and renders investigation types grouped by category", () => {
    renderModal();

    expect(
      screen.getByRole("textbox", {
        name: /search investigation types/i,
      })
    ).toBeInTheDocument();

    expect(screen.getByText("Identity")).toBeInTheDocument();
    expect(screen.getByText("Web & Infrastructure")).toBeInTheDocument();
    expect(screen.getByText("File & Media")).toBeInTheDocument();

    expect(
      screen.getByRole("button", {
        name: /Start a Username investigation/i,
      })
    ).toBeInTheDocument();
  });

  it("filters cards by search across label, description, and category", async () => {
    const user = userEvent.setup();
    renderModal();

    await user.type(
      screen.getByPlaceholderText("Search investigation types..."),
      "malware"
    );

    expect(
      screen.getByRole("button", {
        name: /Start a Malware Intelligence investigation/i,
      })
    ).toBeInTheDocument();

    expect(
      screen.queryByRole("button", {
        name: /Start a Username investigation/i,
      })
    ).not.toBeInTheDocument();
  });

  it("shows an empty state when no type matches the search", async () => {
    const user = userEvent.setup();
    renderModal();

    await user.type(
      screen.getByPlaceholderText("Search investigation types..."),
      "zzzznotarealtype"
    );

    expect(
      screen.getByText("No investigation types match your search")
    ).toBeInTheDocument();
  });

  it("shows the metadata card as unavailable rather than omitting or faking it", () => {
    renderModal();

    const metadataCard = screen.getByRole("button", {
      name: /Start a Metadata investigation/i,
    });

    expect(metadataCard).toBeDisabled();
    expect(within(metadataCard).getByText("Coming soon")).toBeInTheDocument();
  });

  it("renders the dynamic username input after selecting Username", async () => {
    const user = userEvent.setup();
    renderModal();

    await selectType(user, "Username");

    expect(screen.getByLabelText("Username")).toBeInTheDocument();

    expect(
      screen.getByRole("button", {
        name: "Start Investigation",
      })
    ).toBeDisabled();
  });

  it("rejects a full URL for Domain and explains a bare domain is required", async () => {
    const user = userEvent.setup();
    renderModal();

    await selectType(user, "Domain");

    await user.type(
      screen.getByLabelText("Domain"),
      "https://google.com/path"
    );

    expect(
      await screen.findByText(/Enter a bare domain such as example.com/i)
    ).toBeInTheDocument();

    expect(
      screen.getByRole("button", {
        name: "Start Investigation",
      })
    ).toBeDisabled();
  });

  it("enables submission once a valid domain is entered", async () => {
    const user = userEvent.setup();
    renderModal();

    await selectType(user, "Domain");

    await user.type(
      screen.getByLabelText("Domain"),
      "example.com"
    );

    expect(
      screen.getByRole("button", {
        name: "Start Investigation",
      })
    ).toBeEnabled();
  });

  it("detects and displays the malware hash type as the user types", async () => {
    const user = userEvent.setup();
    renderModal();

    await selectType(user, "Malware Intelligence");

    await user.type(
      screen.getByLabelText("File hash"),
      "d41d8cd98f00b204e9800998ecf8427e"
    );

    expect(
      await screen.findByText("MD5")
    ).toBeInTheDocument();

    expect(
      screen.getByRole("button", {
        name: "Start Investigation",
      })
    ).toBeEnabled();
  });

  it("submits a text-based investigation and shows the success transition", async () => {
    const user = userEvent.setup();

    mockedService.createUsername.mockResolvedValue({
      id: "inv-123",
      investigation_type: "username",
      target: "johndoe",
      status: "queued",
      risk_score: null,
      risk_level: null,
      summary: null,
      started_at: null,
      completed_at: null,
      error_message: null,
      created_at: "2026-01-01T00:00:00Z",
      updated_at: "2026-01-01T00:00:00Z",
      results: [],
    });

    renderModal();

    await selectType(user, "Username");

    await user.type(
      screen.getByLabelText("Username"),
      "johndoe"
    );

    await user.click(
      screen.getByRole("button", {
        name: "Start Investigation",
      })
    );

    expect(
      await screen.findByText("Investigation Started")
    ).toBeInTheDocument();

    expect(
      screen.getByText("johndoe")
    ).toBeInTheDocument();

    expect(
      mockedService.createUsername
    ).toHaveBeenCalledWith("johndoe");

    expect(
      mockedService.createUsername
    ).toHaveBeenCalledTimes(1);
  });

  it("prevents a duplicate submission while a request is in flight", async () => {
    const user = userEvent.setup();

    let resolveCreate: (
      value: Awaited<
        ReturnType<typeof investigationService.createUsername>
      >
    ) => void = () => {};

    mockedService.createUsername.mockReturnValue(
      new Promise((resolve) => {
        resolveCreate = resolve;
      })
    );

    renderModal();

    await selectType(user, "Username");

    await user.type(
      screen.getByLabelText("Username"),
      "johndoe"
    );

    const submitButton = screen.getByRole("button", {
      name: "Start Investigation",
    });

    await user.click(submitButton);
    await user.click(submitButton);
    await user.click(submitButton);

    expect(
      mockedService.createUsername
    ).toHaveBeenCalledTimes(1);

    resolveCreate({
      id: "inv-1",
      investigation_type: "username",
      target: "johndoe",
      status: "queued",
      risk_score: null,
      risk_level: null,
      summary: null,
      started_at: null,
      completed_at: null,
      error_message: null,
      created_at: "2026-01-01T00:00:00Z",
      updated_at: "2026-01-01T00:00:00Z",
      results: [],
    });
  });

  it("renders an analyst-friendly message instead of a raw API error", async () => {
    const user = userEvent.setup();

    mockedService.createUsername.mockRejectedValue({
      isAxiosError: true,
      response: {
        status: 400,
        data: {
          detail: "Username contains unsupported characters.",
        },
      },
    });

    renderModal();

    await selectType(user, "Username");

    await user.type(
      screen.getByLabelText("Username"),
      "johndoe"
    );

    await user.click(
      screen.getByRole("button", {
        name: "Start Investigation",
      })
    );

    expect(
      await screen.findByText(
        "Username contains unsupported characters."
      )
    ).toBeInTheDocument();
  });

  it("selects a file for Reverse Image and uses the image upload service method", async () => {
    const user = userEvent.setup();

    mockedService.uploadReverseImage.mockResolvedValue({
      investigation: {
        id: "inv-img-1",
        investigation_type: "reverse_image",
        target: "photo.jpg",
        status: "completed",
        risk_score: null,
        risk_level: null,
        summary: null,
        started_at: null,
        completed_at: null,
        error_message: null,
        created_at: "2026-01-01T00:00:00Z",
        updated_at: "2026-01-01T00:00:00Z",
        results: [],
      },
    });

    renderModal();

    await selectType(user, "Reverse Image");

    const file = new File(
      ["fake-image-bytes"],
      "photo.jpg",
      {
        type: "image/jpeg",
      }
    );

    const input = document.querySelector(
      'input[type="file"]'
    ) as HTMLInputElement;

    await user.upload(input, file);

    expect(
      screen.getByText("photo.jpg")
    ).toBeInTheDocument();

    await user.click(
      screen.getByRole("button", {
        name: "Start Investigation",
      })
    );

    await waitFor(() => {
      expect(
        mockedService.uploadReverseImage
      ).toHaveBeenCalledWith(file);
    });

    expect(
      mockedService.uploadFile
    ).not.toHaveBeenCalled();
  });

  it("requires at least two selections for Composite Risk Assessment", async () => {
    mockedService.list.mockResolvedValue({
      items: [
        {
          id: "a",
          investigation_type: "domain",
          target: "google.com",
          status: "completed",
          risk_level: "low",
          created_at: "2026-01-01T00:00:00Z",
        },
        {
          id: "b",
          investigation_type: "ip_address",
          target: "8.8.8.8",
          status: "completed",
          risk_level: "low",
          created_at: "2026-01-01T00:00:00Z",
        },
      ],
      total: 2,
      page: 1,
      page_size: 25,
      total_pages: 1,
    });

    const user = userEvent.setup();
    renderModal();

    await selectType(
      user,
      "Composite Risk Assessment"
    );

    expect(
      await screen.findByText("google.com")
    ).toBeInTheDocument();

    const submitButton = screen.getByRole("button", {
      name: "Start Investigation",
    });

    expect(submitButton).toBeDisabled();

    await user.click(
      screen.getByRole("option", {
        name: /google.com/i,
      })
    );

    expect(submitButton).toBeDisabled();

    await user.click(
      screen.getByRole("option", {
        name: /8\.8\.8\.8/i,
      })
    );

    expect(submitButton).toBeEnabled();
  });

  it("submits Composite Risk Assessment with the real selected investigation ids", async () => {
    mockedService.list.mockResolvedValue({
      items: [
        {
          id: "inv-a",
          investigation_type: "domain",
          target: "google.com",
          status: "completed",
          risk_level: "low",
          created_at: "2026-01-01T00:00:00Z",
        },
        {
          id: "inv-b",
          investigation_type: "ip_address",
          target: "8.8.8.8",
          status: "completed",
          risk_level: "low",
          created_at: "2026-01-01T00:00:00Z",
        },
      ],
      total: 2,
      page: 1,
      page_size: 25,
      total_pages: 1,
    });

    mockedService.createRiskAssessment.mockResolvedValue({
      id: "inv-composite-1",
      investigation_type: "risk_assessment",
      target: "Composite Risk Assessment",
      status: "queued",
      risk_score: null,
      risk_level: null,
      summary: null,
      started_at: null,
      completed_at: null,
      error_message: null,
      created_at: "2026-01-01T00:00:00Z",
      updated_at: "2026-01-01T00:00:00Z",
      results: [],
    });

    const user = userEvent.setup();
    renderModal();

    await selectType(
      user,
      "Composite Risk Assessment"
    );

    expect(
      await screen.findByText("google.com")
    ).toBeInTheDocument();

    await user.click(
      screen.getByRole("option", {
        name: /google.com/i,
      })
    );

    await user.click(
      screen.getByRole("option", {
        name: /8\.8\.8\.8/i,
      })
    );

    await user.click(
      screen.getByRole("button", {
        name: "Start Investigation",
      })
    );

    await waitFor(() => {
      expect(
        mockedService.createRiskAssessment
      ).toHaveBeenCalledWith(
        ["inv-a", "inv-b"],
        undefined
      );
    });
  });

  it("preselects a type and skips to the form when initialType is provided", () => {
    renderModal({
      initialType: "file",
    });

    expect(
      screen.getByText("File")
    ).toBeInTheDocument();

    expect(
      screen.queryByRole("textbox", {
        name: /search investigation types/i,
      })
    ).not.toBeInTheDocument();
  });

  it("falls back to the type selector when initialType is unavailable", () => {
    renderModal({
      initialType: "metadata",
    });

    expect(
      screen.getByRole("textbox", {
        name: /search investigation types/i,
      })
    ).toBeInTheDocument();
  });
});