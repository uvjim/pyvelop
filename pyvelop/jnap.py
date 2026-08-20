"""Interact with the JNAP API."""

# region #-- imports --#
from __future__ import annotations

import base64
import copy
import json
import logging
from typing import Any, cast

import aiohttp

from .action_registry import ActionDefinition, Actions
from .exceptions import (
    MeshAlreadyInProgress,
    MeshCannotDeleteDevice,
    MeshConnectionError,
    MeshDeviceDbFailure,
    MeshException,
    MeshInvalidCredentials,
    MeshInvalidCredentialsUnlikely,
    MeshInvalidInput,
    MeshInvalidOutput,
    MeshNodeNotPrimary,
    MeshTimeoutError,
)
from .logger import Logger

# endregion

type JnapResponse = dict[str, Any]

_LOGGER = logging.getLogger(__name__)
_LOGGER_VERBOSE = logging.getLogger(f"{__name__}.verbose")


def jnap_url(target: str) -> str:
    """Return the URL that should be used for the request.

    :param target: the API host
    :return: string containing the base URL for all JNAP requests
    """
    return f"http://{target}/JNAP/"


class Request:
    """Represents a request for the API."""

    def __init__(
        self,
        action: str,
        password: str,
        target: str,
        payload: list[dict[str, Any]] | dict[str, Any] | None = None,
        raise_on_error: bool = True,
        session: aiohttp.ClientSession | None = None,
        username: str = "admin",
        redact: bool = True,
        supplementary_redactions: dict[str, set[str]] | None = None,
    ) -> None:
        """Initialise a request.

        :param action: the JNAP action to carry out
        :param password: the password required to communicate with the target
        :param target: the node to send the request to
        :param payload: the additional configuration to pass along with the action
        :param raise_on_error: raise an error if one is found
        :param session: an existing session to use
        :param username: the username required to communicate with the target
        """
        self._action: str = action
        self._creds: str = base64.b64encode(bytes(f"{username}:{password}", "utf-8")).decode("ascii")
        self._log_formatter = Logger(prefix=f"{self.__class__.__name__}.")
        self._payload: list[dict[str, Any]] | dict[str, Any] | None = payload
        self._raise_on_error: bool = raise_on_error
        self._redact: bool = redact
        self._session: aiohttp.ClientSession = (
            session if session is not None else aiohttp.ClientSession(raise_for_status=True)
        )
        self._supplementary_redactions: dict[str, set[str]] = supplementary_redactions or {}

        if self._payload is None:
            self._payload = []
        self._jnap_url: str = jnap_url(target=target)

    async def execute(self, timeout: float = 10) -> Response:
        """Send the request.

        :param timeout: the timeout in seconds for the request, defaults to 10s
        :return: a Response object representing the returned results
        """

        def _build_redactions(key: str) -> set[str]:

            ret: set[str] = set()
            default_redactions: set[str]
            action: ActionDefinition | None = next((a for a in Actions.values() if a.action == key), None)

            if action is not None:
                default_redactions = action.redactions
                ret = default_redactions.union(self._supplementary_redactions.get(action.key, set()))

            return ret

        headers: dict[str, str] = {
            "X-JNAP-Authorization": f"Basic {self._creds}",
            "Content-Type": "application/json; charset=UTF-8",
            "X-JNAP-Action": self._action,
        }

        resp: aiohttp.ClientResponse | None = None
        try:
            resp = await self._session.post(
                url=self._jnap_url,
                headers=headers,
                json=self._payload or {},
                timeout=timeout,  # pyright:ignore[reportArgumentType] if float is passed it's classed as total
            )
            resp_json: JnapResponse = await resp.json()
        except TimeoutError as err:
            raise MeshTimeoutError from err
        except (
            aiohttp.ClientConnectionError,
            aiohttp.ClientConnectorError,
            aiohttp.ContentTypeError,
        ) as err:
            _LOGGER.error(self._log_formatter.format("%s"), err)
            raise MeshConnectionError from None
        except json.JSONDecodeError as err:
            _LOGGER.error(self._log_formatter.format("%s"), err)
            raise err from None

        # region #-- log the response --#
        to_log: dict[str, Any] = {
            "action": self._action,
            "payload": self._payload,
            "response": copy.deepcopy(resp_json),
        }
        if self._action != Actions.TRANSACTION.action:
            if self._redact and to_log["response"].get("result") == "OK":
                to_log["response"].update(
                    {
                        "output": self._log_formatter.redact(
                            to_log["response"].get("output", {}),
                            _build_redactions(self._action),
                        )
                    }
                )
        else:
            for idx, r_json in enumerate(to_log["response"].get("responses", [])):
                action: str = cast(list, self._payload)[idx].get("action", "") if self._payload is not None else ""
                redactions = _build_redactions(action)
                if self._redact and r_json.get("result") == "OK":
                    r_json.update({"output": self._log_formatter.redact(r_json.get("output", {}), redactions)})

        _LOGGER_VERBOSE.debug(json.dumps(to_log))
        # endregion

        ret = Response(action=self.action, data=resp_json, raise_on_error=self._raise_on_error)

        return ret

    # region #-- properties --#
    @property
    def action(self) -> str:
        """Return the action used in the request.

        :return: string containing the action
        """
        return self._action

    @property
    def payload(self) -> list[dict[str, Any]] | dict[str, Any] | None:
        """Return the payload used for the request.

        :return: list[dict] | dict | None containing the payload
        """
        return self._payload

    # endregion


class Response:
    """Represents a response from the API."""

    DATA_KEY_SINGLE: str = "output"
    DATA_KEY_TRANSACTION: str = "responses"
    RESULT_KEY: str = "result"

    def __init__(self, action: str, data: JnapResponse | None, raise_on_error: bool = True) -> None:
        """Initialise the response.

        :param action: The action that was issued in the request to cause the response
        :param data: The JSON response received in response to the API call
        """
        self._action: str = action
        self._data: JnapResponse | None = data
        self._log_formatter = Logger(prefix=f"{self.__class__.__name__}.")
        self._raise_on_error: bool = raise_on_error

        self._process_data()

    def _process_data(self) -> None:
        """Process the given data to check for errors."""

        if self._data is None:
            return

        err: MeshException | None = None

        if self._data.get(self.RESULT_KEY) != "OK":  # seemingly there is an error
            # build a list of the responses - transactions will already be a list
            responses = (
                self._data.get(self.DATA_KEY_TRANSACTION, [])
                if self.action == Actions.TRANSACTION.action
                else [self._data]
            )

            # establish errors and work through them
            err_responses = [resp for resp in responses if resp.get(self.RESULT_KEY) != "OK"]
            for resp in err_responses:  # loop through the responses
                err = None
                if resp is None:
                    err = MeshInvalidOutput(resp)
                elif resp.get(self.RESULT_KEY) == "_ErrorInvalidInput":
                    err = MeshInvalidInput(resp.get("error"))
                elif resp.get(self.RESULT_KEY) == "_ErrorInvalidOutput":
                    err = MeshInvalidOutput(resp.get("error"))
                elif resp.get(self.RESULT_KEY) == "_ErrorUnauthorized":
                    err = MeshInvalidCredentials()
                elif resp.get(self.RESULT_KEY) == "_ErrorUnknownAction":
                    action = (
                        resp.get("error")
                        if self.action == Actions.TRANSACTION.action
                        else f"Unknown action URI '{self.action}'"
                    )
                    err = MeshInvalidInput(action)
                elif resp.get(self.RESULT_KEY) == "ErrorAutoChannelSelectionAlreadyInProgress":
                    err = MeshAlreadyInProgress()
                elif resp.get(self.RESULT_KEY) == "ErrorCannotDeleteDevice":
                    err = MeshCannotDeleteDevice()
                elif resp.get(self.RESULT_KEY) == "ErrorDeviceDBFailure":
                    err = MeshDeviceDbFailure(resp.get(self.DATA_KEY_SINGLE, {}).get("ErrorInfo", ""))
                elif resp.get(self.RESULT_KEY) == "ErrorDeviceNotInMasterMode":
                    err = MeshNodeNotPrimary()
                elif resp.get(self.RESULT_KEY) == "ErrorInvalidWANSchedule":
                    err = MeshInvalidInput("Invalid WAN Schedule")
                elif resp.get(self.RESULT_KEY) == "ErrorRulesOverlap":
                    err = MeshInvalidInput("Rules Overlap")
                elif resp.get(self.RESULT_KEY) == "ErrorUnknownDevice":
                    err = MeshInvalidInput("Unknown Device")
                elif resp.get(self.RESULT_KEY, "").startswith("_"):
                    err = MeshInvalidInput(f"{resp.get(self.RESULT_KEY)}: '{self.action}'")
                else:  # don't know the error, log and raise exception
                    _LOGGER.error(
                        self._log_formatter.format("unknown error received: %s"),
                        self._data,
                    )
                    err = MeshException(json.dumps(resp.get(self.RESULT_KEY)))

                # occasionaly see an error stating that credentials are invalid even though
                # an action in the transaction has already been processed, so they can't be invalid
                # we'll raise a different exception to cover that so the caller can respond accordingly.
                if isinstance(err, MeshInvalidCredentials) and len(err_responses) != len(responses):
                    err = MeshInvalidCredentialsUnlikely()

                if err:  # break out of the for loop if we have an error
                    break

        if err and self._raise_on_error:
            raise err

    # region #-- properties --#
    @property
    def action(self) -> str:
        """Return the action that resulted in the response.

        :return: string containing the action
        """
        return self._action

    @property
    def data(self) -> JnapResponse | list[JnapResponse] | None:
        """Return the response data."""

        if self._data is None:
            return None

        ret = (
            self._data.get(self.DATA_KEY_TRANSACTION)
            if self.action == Actions.TRANSACTION.action
            else self._data.get(self.DATA_KEY_SINGLE, self._data)
        )

        return ret

    # endregion
