use crate::AppEvent;
use tokio::sync::mpsc;
#[derive(Clone)]
pub struct AppEventSender(mpsc::Sender<AppEvent>);
impl AppEventSender {
    pub fn channel() -> (Self, mpsc::Receiver<AppEvent>) {
        let (tx, rx) = mpsc::channel(64);
        (Self(tx), rx)
    }
    pub async fn send(&self, e: AppEvent) -> Result<(), AppEvent> {
        self.0.send(e).await.map_err(|e| e.0)
    }
    pub fn try_send(&self, e: AppEvent) -> Result<(), Box<AppEvent>> {
        self.0.try_send(e).map_err(|e| Box::new(e.into_inner()))
    }
    pub(crate) fn blocking_send(&self, e: AppEvent) -> Result<(), Box<AppEvent>> {
        self.0.blocking_send(e).map_err(|e| Box::new(e.0))
    }
}
